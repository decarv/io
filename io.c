/* io.c
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 *
 * This code is based on: https://git.kernel.dk/cgit/liburing/tree/examples/proxy.c
 * (C) 2024 Jens Axboe <axboe@kernel.dk>
 *
 *
 *
 *
 * TODO:
 *  - Replace the following functionality (from pgagroal):
 *       if (config->idle_timeout > 0)
 *       {
 *          ev_periodic_init (&idle_timeout, idle_timeout_cb, 0.,
 *                            MAX(1. * config->idle_timeout / 2., 5.), 0);
 *          ev_periodic_start (main_loop, &idle_timeout);
 *       }
 *       if (config->max_connection_age > 0)
 *       {
 *          ev_periodic_init (&max_connection_age, max_connection_age_cb, 0.,
 *                            MAX(1. * config->max_connection_age / 2., 5.), 0);
 *          ev_periodic_start (main_loop, &max_connection_age);
 *       }
 *       if (config->validation == VALIDATION_BACKGROUND)
 *       {
 *          ev_periodic_init (&validation, validation_cb, 0.,
 *                            MAX(1. * config->background_interval, 5.), 0);
 *          ev_periodic_start (main_loop, &validation);
 *       }
 *       if (config->disconnect_client > 0)
 *       {
 *          ev_periodic_init (&disconnect_client, disconnect_client_cb, 0.,
 *                            MIN(300., MAX(1. * config->disconnect_client / 2., 1.)), 0);
 *          ev_periodic_start (main_loop, &disconnect_client);
 *       }
 */

/* system */
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <liburing.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <err.h>
#include <sys/mman.h>
#include <signal.h>
#include <sys/signalfd.h>

/* io lib */
#include "io.h"

static struct io_configuration ctx = { 0 };

#define CLOSE_FD          1 << 1
#define REPLENISH_BUFFERS 1 << 2

/*
 * ACCEPT | RECEIVE
 */

io_handler handlers[] =
{
   [__ACCEPT] = io_accept_handler,
   [__RECEIVE] = io_receive_handler,
   [__SEND] = io_send_handler,
   [__SIGNAL] = io_signal_handler,
   [__SOCKET] = io_socket_handler,
   [__CONNECT] = io_connect_handler,
};

void
next_bid(int* bid)
{
   *bid = (*bid + 1) % ctx.buf_count;
}

int
io_get_entry(struct io* io, int fd)
{
   int free_entry = -1;
   for (int i = 0; i < FDS; i++)
   {
      int registered_fd = io->fd_table[i].fd;
      if (registered_fd == fd)
      {
         return i;
      }
      if (free_entry < 0 && registered_fd < 0)
      {
         free_entry = i;
      }
   }

   if (free_entry < 0)
   {
      fprintf(stderr, "io_get_entry\n");
      return free_entry;
   }

   /* register fd */
   io->fd_table[free_entry].fd = fd;

   return free_entry;
}

int
io_register_signal(struct io* io, int signum, _signal_event_cb callback)
{
   sigaddset(&io->signal_mask, signum);

   struct fd_entry* entry = &io->fd_table[0]; /* signal fd is always the first */

   switch (signum)
   {
      case SIGTERM:
         entry->callbacks[__SIGTERM].signal_cb = callback;
         break;
      case SIGHUP:
         entry->callbacks[__SIGHUP].signal_cb = callback;
         break;
      case SIGINT:
         entry->callbacks[__SIGINT].signal_cb = callback;
         break;
      case SIGTRAP:
         entry->callbacks[__SIGTRAP].signal_cb = callback;
         break;
      case SIGABRT:
         entry->callbacks[__SIGABRT].signal_cb = callback;
         break;
      case SIGALRM:
         entry->callbacks[__SIGALRM].signal_cb = callback;
         break;
      default:
         fprintf(stderr, "No support for signal %d", signum);
         return 1;
   }

   return 0;
}

int
io_signals_init(struct io* io)
{
   int entry_index;

   sigemptyset(&io->signal_mask);

   if (sigprocmask(SIG_BLOCK, &io->signal_mask, NULL) == -1)
   {
      perror("sigprocmask");
      return -1;
   }

   int signal_fd = signalfd(-1, &io->signal_mask, 0);
   if (signal_fd == -1)
   {
      perror("signalfd");
      return -1;
   }

   entry_index = io_get_entry(io, signal_fd);
   if (entry_index != 0)
   {
      fprintf(stderr, "io_initialize_signals: not supposed to happen\n");
      exit(1);
   }

   return 0;
}

int
io_signal_handler(struct io* io, struct io_uring_cqe* cqe, void** buf, int* bid)
{
   struct signalfd_siginfo fdsi;
//   ssize_t s = read(cqe->fd, &fdsi, sizeof(struct signalfd_siginfo));
//   if (s != sizeof(struct signalfd_siginfo)) {
//      perror("read");
//      return -1;
//   }

   int signum = fdsi.ssi_signo;
   struct fd_entry* entry = &io->fd_table[0];
   return entry->callbacks[signum].signal_cb(signum);
}

int
io_register_event(struct io* io, int fd, int event, io_event_cb callback, void* buf, size_t buf_len)
{
   int ret = 0;
   int registered = 0;
   struct fd_entry* entry = NULL;
   int entry_index = -1;

   if (fd < 0)
   {
      fprintf(stderr, "io_register_event: Invalid file descriptor: %d\n", fd);
      return 1;
   }
   if (event < 0 || event >= EVENTS_NR)
   {
      fprintf(stderr, "io_register_event: Invalid event number: %d\n", event);
      return 1;
   }

   entry_index = io_get_entry(io, fd);
   if (entry_index < 0)
   {
      fprintf(stderr, "io_register_event: Not enough room for another fd\n");
      return 1;
   }

   entry = &io->fd_table[entry_index];

   if (event & ACCEPT)
   {
      io_prepare_accept(io, fd);
      entry->callbacks[__ACCEPT].event_cb = callback;
      registered++;
   }
   if (event & RECEIVE)
   {
      io_prepare_receive(io, fd);
      entry->callbacks[__RECEIVE].event_cb = callback;
      registered++;
   }
   if (event & SEND)
   {
      io_prepare_send(io, fd, buf, buf_len);
      entry->callbacks[__SEND].event_cb = callback;
      registered++;
   }

   ret = registered > 0 ? 0 : 1;

   return ret;
}

void
io_encode_data(struct io_uring_sqe* sqe, uint8_t op, uint16_t id, uint16_t bid, uint16_t fd)
{
   struct user_data ud = {
      .op = op,
      .id = id,
      .bid = bid,
      .fd = fd,
      .rsv = 0,
   };
   io_uring_sqe_set_data64(sqe, ud.as_u64);
}

struct
user_data
io_decode_data(struct io_uring_cqe* cqe)
{
   struct user_data ud = { .as_u64 = cqe->user_data };
   return ud;
}

int
io_decode_op(struct io_uring_cqe* cqe)
{
   struct user_data ud = { .as_u64 = cqe->user_data };
   return ud.op;
}

int
io_cqe_to_bid(struct io_uring_cqe* cqe)
{
   struct user_data ud = { .as_u64 = cqe->user_data };
   return ud.bid;
}

int
io_prepare_connect(struct io* io, int fd, union io_sockaddr addr)
{
   int ret;
   struct io_uring_sqe* sqe = io_get_sqe(io);

   /* expects addr to be set correctly */

   if (ctx.ipv6)
   {
      io_uring_prep_connect(sqe, fd, (struct sockaddr*) &addr.addr6, sizeof(struct sockaddr_in6));
   }
   else
   {
      io_uring_prep_connect(sqe, fd, (struct sockaddr*) &addr.addr4, sizeof(struct sockaddr_in));
   }

   io_encode_data(sqe, CONNECT, io->id, 0, fd);

   return 0;
}

int
io_prepare_socket(struct io* io)
{
   struct io_uring_sqe* sqe = io_get_sqe(io);
   int domain;
   if (ctx.ipv6)
   {
      domain = AF_INET6;
   }
   else
   {
      domain = AF_INET;
   }
   io_uring_prep_socket(sqe, domain, SOCK_STREAM, 0, 0); /* TODO: WHAT CAN BE USED HERE ? */
   io_encode_data(sqe, SOCKET, io->id, 0, 0);
   return 0;
}

int
io_handle_socket(struct io* io, struct io_uring_cqe* cqe)
{
   return 1;
}

int
io_init(struct io** io, void* data)
{
   int ret;

   *io = calloc(1, sizeof(struct io));
   if (!*io)
   {
      fprintf(stderr, "io_init: calloc\n");
      return 1;
   }

   ret = io_uring_queue_init_params(ctx.entries, &(*io)->ring, &ctx.params);
   if (ret)
   {
      fprintf(stderr, "io_init: io_uring_queue_init_params: %s\n", strerror(-ret));
      return 1;
   }

   io_setup_buffers(*io);

   for (int i = 0; i < FDS; i++)
   {
      (*io)->fd_table[i].fd = -1;
   }

   (*io)->data = data;

   io_signals_init(*io);

   return 0;
}

int
io_context_setup(struct io_configuration_options config)
{
   int ret;

   /* set config */

   ctx.napi = config.napi;
   ctx.sqpoll = config.sqpoll;
   ctx.use_huge = config.use_huge;
   ctx.defer_tw = config.defer_tw;
   ctx.snd_ring = config.snd_ring;
   ctx.snd_bundle = config.snd_bundle;
   ctx.fixed_files = config.fixed_files;

   ctx.buf_count = config.buf_count;

   if (ctx.defer_tw && ctx.sqpoll)
   {
      fprintf(stderr, "Cannot use DEFER_TW and SQPOLL at the same time\n");
      exit(1);
   }

   /* setup params TODO: pull from opts */

   ctx.entries = (1 << 10);
   ctx.params.cq_entries = (1 << 10);
   ctx.params.flags = 0;
   ctx.params.flags |= IORING_SETUP_SINGLE_ISSUER; /* TODO: makes sense for pgagroal? */
   ctx.params.flags |= IORING_SETUP_CLAMP;
   ctx.params.flags |= IORING_SETUP_CQSIZE;

   /* default configuration */

   if (ctx.defer_tw)
   {
      ctx.params.flags |= IORING_SETUP_DEFER_TASKRUN; /* overwritten by SQPOLL */
   }
   if (ctx.sqpoll)
   {
      ctx.params.flags |= IORING_SETUP_SQPOLL;
      ctx.params.sq_thread_idle = config.sq_thread_idle;
   }
   if (!ctx.sqpoll && !ctx.defer_tw)
   {
      ctx.params.flags |= IORING_SETUP_COOP_TASKRUN;
   }
   if (!ctx.buf_count)
   {
      ctx.buf_count = BUFFER_COUNT;
   }
   if (!ctx.buf_size)
   {
      ctx.buf_size = BUFFER_SIZE;
   }
   ctx.br_mask = (ctx.buf_count - 1);

   if (ctx.fixed_files)
   {
      fprintf(stderr, "io_context_setup: no support for fixed files\n"); /* TODO */
      exit(1);
   }

   return 0;
}

struct io_uring_sqe*
io_get_sqe(struct io* io)
{
   struct io_uring* ring = &io->ring;
   struct io_uring_sqe* sqe;
   do
   {
      sqe = io_uring_get_sqe(ring);
      if (sqe)
      {
         return sqe;
      }
      else
      {
         io_uring_sqring_wait(ring);
      }
   }
   while (1);
}

int
io_prepare_accept(struct io* io, int fd)
{
   struct io_uring_sqe* sqe = io_get_sqe(io);

   io_encode_data(sqe, __ACCEPT, io->id, io->bid, fd);

   io_uring_prep_multishot_accept(sqe, fd, NULL, NULL, 0);

   return 0;
}

int
io_prepare_receive(struct io* io, int fd)
{
   int ret;
   struct io_uring_sqe* sqe = io_get_sqe(io);
   int bid = 0;

   io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);

   io_encode_data(sqe, __RECEIVE, io->id, 0, fd);

   sqe->flags |= IOSQE_BUFFER_SELECT;
   sqe->buf_group = 0;

   return 0;
}

int
io_prepare_send(struct io* io, int fd, void* buf, size_t data_len)
{
   int res = 0;
   struct io_uring_sqe* sqe = io_get_sqe(io);

   io_uring_prep_send(sqe, fd, buf, data_len, MSG_WAITALL | MSG_NOSIGNAL); /* TODO: why these flags? */

   io_encode_data(sqe, SEND, io->id, 0, fd);

   return 0;
}

int
io_loop(struct io* io)
{
   struct __kernel_timespec active_ts, idle_ts;
   int flags;
   static int wait_usec = 1000000;
   idle_ts.tv_sec = 0;
   idle_ts.tv_nsec = 100000000LL;
   active_ts = idle_ts;
   if (wait_usec > 1000000)
   {
      active_ts.tv_sec = wait_usec / 1000000;
      wait_usec -= active_ts.tv_sec * 1000000;
   }
   active_ts.tv_nsec = wait_usec * 1000;

   flags = 0;
   while (1)
   {
      struct __kernel_timespec* ts = &idle_ts;
      struct io_uring_cqe* cqe;
      unsigned int head;
      int ret, events, to_wait;

      to_wait = 1; /* wait for any 1 */

      io_uring_submit_and_wait_timeout(&io->ring, &cqe, to_wait, ts, NULL);

      /* Good idea to leave here to see what happens */
      if (*io->ring.cq.koverflow)
      {
         printf("overflow %u\n", *io->ring.cq.koverflow);
         exit(1);
      }

      if (*io->ring.sq.kflags & IORING_SQ_CQ_OVERFLOW)
      {
         printf("saw overflow\n");
         exit(1);
      }

      events = 0;
      io_uring_for_each_cqe(&(io->ring), head, cqe)
      {
         if (io_handle_event(io, cqe))
         {
            fprintf(stderr, "io_loop: io_handle_event\n");
            return 1;
         }
         events++;
      }

      if (events)
      {
         io_uring_cq_advance(&io->ring, events);  /* batch marking as seen */
      }

      /* TODO: housekeeping ? */

   }

   return 0;
}

int
io_cleanup(struct io* io)
{
   if (io)
   {
      io_uring_queue_exit(&io->ring);
      if (io->in_br.buf)
      {
         free(io->in_br.buf);
      }
      free(io);
   }
   return 0;
}

int
io_setup_buffers(struct io* io)
{
   int ret;
   void* ptr;

   ret = io_setup_buffer_ring(io);

   struct io_buf_ring* cbr = &io->in_br;

   if (ctx.use_huge)
   {
      fprintf(stderr, "io_setup_buffers: use_huge not implemented yet\n"); /* TODO */
   }
   if (posix_memalign(&cbr->buf, ALIGNMENT, ctx.buf_count * ctx.buf_size))
   {
      perror("io_setup_buffer_ring: posix_memalign");
      return 1;
   }

   cbr->br = io_uring_setup_buf_ring(&io->ring, ctx.buf_count, 0, 0, &ret);
   if (!cbr->br)
   {
      fprintf(stderr, "Buffer ring register failed %d\n", ret);
      return 1;
   }

   ptr = cbr->buf;
   for (int i = 0; i < ctx.buf_count; i++)
   {
      printf("add bid %d, data %p\n", i, ptr);
      io_uring_buf_ring_add(cbr->br, ptr, ctx.buf_size, i, ctx.br_mask, i);
      ptr += ctx.buf_size;
   }
   io_uring_buf_ring_advance(cbr->br, ctx.buf_count);

   io->bid = 0;
   return ret;
}

int
io_setup_buffer_ring(struct io* io)
{
   int ret;

   return 0;
}

/************ HANDLERS
 *
 */

int
io_accept_handler(struct io* io, struct io_uring_cqe* cqe, void** buf, int* bid)
{
   return 0;
}

int
io_connect_handler(struct io* io, struct io_uring_cqe* cqe, void** buf, int* bid)
{
   return 0;
}

int
io_receive_handler(struct io* io, struct io_uring_cqe* cqe, void** send_buf_base, int* bid)
{
   /*
    * If the buffer is too small it will overflow and apparently there is nothing we can do about it...
    */
   struct io_buf_ring* iobr = &io->in_br;
   *send_buf_base = (void*) (iobr->buf + *bid * ctx.buf_size);
   struct io_uring_buf* buf;
   void* data;
   int pending_recv = 0;
   int this_bytes;
   int nr_packets = 0;
   int in_bytes;

   if (cqe->res == -ENOBUFS)
   {
      fprintf(stderr, "io_receive_handler: Not enough buffers\n");
      return REPLENISH_BUFFERS;
   }

   if (!(cqe->flags & IORING_CQE_F_BUFFER))
   {
      pending_recv = 0;

      if (!(cqe->res))
      {
         return CLOSE_FD;
      }
   }

   in_bytes = cqe->res;

//   printf("[DEBUG] Received Bytes: %d\n", in_bytes);

   /* If the size of the buffer (this_bytes) is greater than the size of the received bytes, then continue.
    * Otherwise, we iterate over another buffer
    */
   while (in_bytes)
   {
      buf = &(iobr->br->bufs[*bid]);
      data = (char*) buf->addr;
      this_bytes = buf->len;
      /* Break if the received bytes is smaller than buffer length.
       * Otherwise, continue iterating over the buffers.
       */
      if (this_bytes > in_bytes)
      {
         this_bytes = in_bytes;
      }

      in_bytes -= this_bytes;

//      printf("[DEBUG] %s\n", (char*) data);

      *bid = (*bid + 1) & (ctx.buf_count - 1);
      nr_packets++;
   }

   io_uring_buf_ring_advance(iobr->br, 1);

   return 0;
}

int
io_send_handler(struct io* io, struct io_uring_cqe* cqe, void** buf, int* bid)
{
   int ret;
   int fd;

   /* replenish buffer */
   io_uring_buf_ring_add(io->in_br.br, *buf, ctx.buf_size, *bid, ctx.br_mask, 1);

   return 0;
}

int
io_socket_handler(struct io* io, struct io_uring_cqe* cqe, void** buf, int* bid)
{
   int ret;
   int fd;

   fd = cqe->res;

   /* TODO: do something cool */

   return 0;
}

int
io_handle_event(struct io* io, struct io_uring_cqe* cqe)
{
   int fd = -1;
   int res_fd = -1;
   int event = -1;
   int ret = 0;
   int entry_index = -1;
   void* buf = NULL;
   io_handler handler;
   struct fd_entry* entry = NULL;

   struct user_data ud = io_decode_data(cqe);

   event = ud.op;

   handler = handlers[event];
   if (!handler)
   {
      fprintf(stderr, "io_handle_event: handler does not exist for event %d\n", event);
      return 1;
   }

   int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
   int bid_start = bid;
   int bid_end = bid;

   fd = ud.fd;
   entry_index = io_table_lookup(io, fd);
   if (entry_index < 0)
   {
      fprintf(stderr, "io_handle_event\n");
      return 1;
   }

   ret = handler(io, cqe, &buf, &bid_end);

   if (ret & CLOSE_FD)
   {
      // clean entry
      close(fd);
      io->fd_table[entry_index].fd = -1;
      return 0;
   }
   else if (ret & REPLENISH_BUFFERS)
   {
      printf("INFO: Replenish buffers triggered\n");
      io_prepare_send(io, fd, buf, cqe->res);

      io_prepare_receive(io, fd);
      return 0;
   }
   else if (ret)
   {
      fprintf(stderr, "io_handle_event: handler error\n");
      return 1;
   }

   int count;
   if (bid_end >= bid_start)
   {
      count = (bid_end - bid_start);
   }
   else
   {
      count = (bid_end + ctx.buf_count - bid_start);
   }

   res_fd = fd;
   if (event == __ACCEPT)
   {
      res_fd = cqe->res;
   }

   int buf_len;
   if (event == __RECEIVE)
   {
      buf_len = cqe->res;
   }

   entry = &io->fd_table[entry_index];
   if (entry->callbacks[event].event_cb)
   {
      ret = entry->callbacks[event].event_cb(io->data, res_fd, ret, buf, buf_len);
   }

   if (buf)
   {
      /* replenish buffers */
      for (int i = bid_start; i != bid_end; i = (i + 1) & (ctx.buf_count - 1))
      {
         io_uring_buf_ring_add(io->in_br.br, (void*)io->in_br.br->bufs[bid].addr, ctx.buf_size, bid, ctx.br_mask, 0);
      }
      io_uring_buf_ring_advance(io->in_br.br, count);
   }

   return ret;
}

int
io_table_lookup(struct io* io, int fd)
{
   struct fd_entry* entry;
   for (int i = 0; i < FDS; i++)
   {
      entry = &io->fd_table[i];
      if (entry->fd == fd)
      {
         return i;
      }
   }
   fprintf(stderr, "io_table_lookup\n");
   return -1;
}