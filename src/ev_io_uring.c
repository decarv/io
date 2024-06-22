/* io.c
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 *
 * This code is based on: https://git.kernel.dk/cgit/liburing/tree/examples/proxy.c
 * (C) 2024 Jens Axboe <axboe@kernel.dk>
 *
 */

/* ev */
#include "../include/ev_io_uring.h"

/* system */
#include <sys/eventfd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <liburing.h>
#include <sys/socket.h>
#include <netdb.h>
#include <signal.h>
#include <sys/timerfd.h>
#include <time.h>
#include <sys/poll.h>

static struct ev_context ctx = { 0 };
static int signal_fd;

#define CLOSE_FD          1 << 1
#define REPLENISH_BUFFERS 1 << 2

io_handler handlers[] =
{
   [__ACCEPT] = io_accept_handler,
   [__RECEIVE] = io_receive_handler,
   [__SEND] = io_send_handler,
   [__SIGNAL] = io_signal_handler,
   [__SOCKET] = io_socket_handler,
   [__CONNECT] = io_connect_handler,
   [OP_PERIODIC] = periodic_handler,
};

/**
 * Event Interfaces
 *  1. ev_init: Init the event handling context
 *  2. {signal|periodic|io}_init: returns an fd
 *  3. ev_register_{signal|periodic|io}: registers the file descriptor
 */

/*
 * File I/O Event Handling
 */


/*
 * Signal Events
 */


int
signal_init(struct ev* ev, int signum, signal_cb cb)
{
   int fd;
   int ret;
   sigaddset(&ev->sigset, signum);

   ret = sigprocmask(SIG_BLOCK, &ev->sigset, NULL);
   if (ret == -1)
   {
      fprintf(stdout, "sigprocmask\n");
      return 1;
   }

   for (int i = 0; i < MAX_SIGNALS; i++)
   {
      if (ev->signal_table[i].signum == -1)
      {
         ev->signal_table[i].signum = signum;
         ev->signal_table[i].callback = cb;
         return 0;
      }
   }

//   fd = signalfd(-1, &mask, 0);  /* TODO: SFD_NONBLOCK | SFD_CLOEXEC Flags? */
//   if (fd == -1)
//   {
//      perror("signalfd");
//      return -1;
//   }

   return 1;
}


int
signal_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int* x)
{
   return 0;
}

/*
 * Alarm Event Handling
 */

int
periodic_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int* x)
{
   return 0;
}

/*
 * Utils
 */

void
next_bid(int* bid)
{
   *bid = (*bid + 1) % ctx.buf_count;
}

int
register_fd(struct ev* ev, int fd)
{
   int free_entry = -1;
   for (int i = 0; i < FDS; i++)
   {
      int registered_fd = ev->fd_table[i].fd;
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
      fprintf(stderr, "register_fd\n");
      return free_entry;
   }

   /* register fd */
   ev->fd_table[free_entry].fd = fd;

   return free_entry;
}


int
register_event(struct ev* ev, int fd, int event, union event_cb callback, void* buf, size_t buf_len)
{
   int ret = 0;
   int entry_index = -1;
   struct fd_entry* entry = NULL;

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

   entry_index = register_fd(ev, fd);
   if (entry_index < 0)
   {
      fprintf(stderr, "io_register_event: Not enough room for another fd\n");
      return 1;
   }

   entry = &ev->fd_table[entry_index];

   switch (event)
   {
      case ACCEPT:
         io_prepare_accept(ev, fd);
         entry->callbacks[__ACCEPT].io = callback.io;
         break;
      case RECEIVE:
         io_prepare_receive(ev, fd);
         entry->callbacks[__RECEIVE].io = callback.io;
         break;
      case SEND:
         io_prepare_send(ev, fd, buf, buf_len);
         entry->callbacks[__SEND].io = callback.io;
         break;
      case PERIODIC:
         prepare_periodic(ev, fd);
         entry->callbacks[__PERIODIC].periodic = callback.periodic;
         break;
      case SIGNAL:
//         io_prepare_signal(io, fd);
         entry->callbacks[__SIGNAL].signal = callback.signal;
         break;
      default:
         return 1;
   }

   return 0;
}

static void msec_to_ts(struct __kernel_timespec *ts, unsigned int msec)
{
   ts->tv_sec = msec / 1000;
   ts->tv_nsec = (msec % 1000) * 1000000;
}

int
periodic_init(struct ev * ev, int msec)
{
   struct __kernel_timespec ts = ev->ts[ev->periodic_count++];
   ts.tv_sec = msec / 1000;
   ts.tv_nsec = (msec % 1000) * 1000000;

   struct io_uring_sqe *sqe = io_uring_get_sqe(&ev->ring);
   encode_user_data(sqe, OP_PERIODIC, 0, 0, 0);
   io_uring_prep_timeout(sqe, &ts, 0, IORING_TIMEOUT_MULTISHOT);
   return 0;
}

int
periodic_init2(double interval)
{
   int fd;
   struct itimerspec new_value;
   memset(&new_value,0,sizeof(struct itimerspec));

   fd = timerfd_create(CLOCK_MONOTONIC,0);
   if (fd == -1)
   {
      perror("timerfd_create\n");
      return 1;
   }

   new_value.it_interval.tv_sec = (int)interval;
   new_value.it_interval.tv_nsec = (interval - (int)interval) * 1e9;
   new_value.it_value.tv_sec = (int)interval;
   new_value.it_value.tv_nsec = (interval - (int)interval) * 1e9;

   if (timerfd_settime(fd,0,&new_value,NULL) == -1)
   {
      perror("timerfd_settime");
      return -1;
   }

   return fd;
}


int
prepare_periodic(struct io* io,int fd)
{
   return io_prepare_read(io,fd,__PERIODIC);
}

void
encode_user_data(struct io_uring_sqe* sqe,uint8_t event,uint16_t id,uint16_t bid,uint16_t fd)
{
   struct user_data ud = {
      .event = event,
      .id = id,
      .bid = bid,
      .fd = fd,
      .rsv = 0,
   };
   io_uring_sqe_set_data64(sqe,ud.as_u64);
}

struct
user_data
decode_user_data(struct io_uring_cqe* cqe)
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
io_prepare_read(struct io* io,int fd,int op)
{
   struct io_uring_sqe* sqe = io_get_sqe(io);
   io_uring_prep_read(sqe,fd,&io->expirations,sizeof(io->expirations),0);
   encode_user_data(sqe,op,io->id,io->bid,fd);
   return 0;
}

int
io_prepare_connect(struct io* io,int fd,union io_sockaddr addr)
{
   int ret;
   struct io_uring_sqe* sqe = io_get_sqe(io);

   /* expects addr to be set correctly */

   if (ctx.ipv6)
   {
      io_uring_prep_connect(sqe,fd,(struct sockaddr*) &addr.addr6,sizeof(struct sockaddr_in6));
   }
   else
   {
      io_uring_prep_connect(sqe,fd,(struct sockaddr*) &addr.addr4,sizeof(struct sockaddr_in));
   }

   encode_user_data(sqe,CONNECT,io->id,0,fd);

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
   io_uring_prep_socket(sqe,domain,SOCK_STREAM,0,0);     /* TODO: WHAT CAN BE USED HERE ? */
   encode_user_data(sqe,SOCKET,io->id,0,0);
   return 0;
}

int
io_handle_socket(struct io* io,struct io_uring_cqe* cqe)
{
   return 1;
}

int
ev_init(struct io** ev_out,void* data)
{
   int ret;
   struct io* ev;

   *ev_out = calloc(1,sizeof(struct io));
   if (!*ev_out)
   {
      fprintf(stderr,"io_init: calloc\n");
      return 1;
   }

   ev = *ev_out;

   ret = io_uring_queue_init_params(ctx.entries,&ev->ring,&ctx.params);
   if (ret)
   {
      fprintf(stderr,"io_init: io_uring_queue_init_params: %s\n",strerror(-ret));
      fprintf(stderr, "Make sure to setup context with io_context_setup\n");
      return 1;
   }

   io_setup_buffers(ev);

   for (int i = 0; i < FDS; i++)
   {
      ev->fd_table[i].fd = -1;
   }
   for (int i = 0; i < MAX_SIGNALS; i++)
   {
      ev->signal_table[i].signum = -1;
   }

   ev->data = data;

   sigemptyset(&ev->sigset);
//   if (pipe(ctx.pipe_fds) == -1)
//   {
//      perror("pipe");
//      return 1;
//   }
//
//   int flags = fcntl(ctx.pipe_fds[0], F_GETFL, 0);
//   fcntl(ctx.pipe_fds[0], F_SETFL, flags | O_NONBLOCK);
//
//   io_prepare_read(*io, ctx.pipe_fds[0], __SIGNAL);

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

   encode_user_data(sqe, __ACCEPT, io->id, io->bid, fd);

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

   encode_user_data(sqe, __RECEIVE, io->id, 0, fd);

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

   encode_user_data(sqe, SEND, io->id, 0, fd);

   return 0;
}

int
ev_loop(struct ev* ev)
{
   struct __kernel_timespec active_ts, idle_ts;
   siginfo_t siginfo;
   sigset_t pending;
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

      io_uring_submit_and_wait(&ev->ring, 0);

      /* Good idea to leave here to see what happens */
      if (*ev->ring.cq.koverflow)
      {
         printf("overflow %u\n", *ev->ring.cq.koverflow);
         exit(1);
      }

      if (*ev->ring.sq.kflags & IORING_SQ_CQ_OVERFLOW)
      {
         printf("saw overflow\n");
         exit(1);
      }

      events = 0;
      io_uring_for_each_cqe(&(ev->ring), head, cqe)
      {
         if (handle_event(ev, cqe))
         {
            fprintf(stderr, "ev_loop: io_handle_event\n");
            return 1;
         }
         events++;
      }

      if (events)
      {
         io_uring_cq_advance(&ev->ring, events);  /* batch marking as seen */
      }

      /* TODO: housekeeping ? */

      ret = sigwaitinfo(&ev->sigset, &siginfo);
      if (ret > 0)
      {
         ret = handle_signal(ev, siginfo.si_signo);
         if (ret)
         {
            fprintf(stderr, "Signal handler not found\n");
            return 1;
         }
      }
   }

   return 0;
}

int
handle_signal(struct io* io, int signum)
{
   for (int i = 0; i < MAX_SIGNALS; i++)
   {
      if (io->signal_table[i].signum == signum)
      {
         return io->signal_table[i].callback(io->data, signum);
      }
   }
   return 1;
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

bool
is_periodic2(int e)
{
   return (e == OP_PERIODIC);
}

bool
is_periodic(int e)
{
   return (e == OP_PERIODIC);
}

bool
is_signal(int e)
{
   return (e == __SIGNAL);
}

int
handle_event(struct ev* ev, struct io_uring_cqe* cqe)
{
   int fd = -1;
   int res_fd = -1;
   int event = -1;
   int ret = 0;
   int entry_index = -1;
   void* buf = NULL;
   io_handler handler;
   struct fd_entry* entry = NULL;

   struct user_data ud = decode_user_data(cqe);

   event = ud.event;
   fd = ud.fd;

   handler = handlers[event];
   if (!handler)
   {
      fprintf(stderr, "io_handle_event: handler does not exist for event %d\n", event);
      return 1;
   }

   int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
   int bid_start = bid;
   int bid_end = bid;

   entry_index = fd_table_lookup(ev, fd);
   if (entry_index < 0)
   {
      fprintf(stderr, "io_handle_event\n");
      return 1;
   }

   ret = handler(ev, cqe, &buf, &bid_end);

   if (ret & CLOSE_FD)
   {
      /* clean entry */
      close(fd);
      ev->fd_table[entry_index].fd = -1;
      return 0;
   }
   else if (ret & REPLENISH_BUFFERS)
   {
      printf("INFO: Replenish buffers triggered\n");
      io_prepare_send(ev, fd, buf, cqe->res);

      io_prepare_receive(ev, fd);
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



   if (is_periodic(event))
   {
      entry = &ev->periodic_table[entry_index];
      ret = entry->callbacks[event].periodic(ev->data, 0);
      if (ret)
      {
         fprintf(stderr, "handle_event: callback[event].periodic\n");
         return 1;
      }

      /* if is_periodic2 rearm periodic and exit */
//      prepare_periodic(ev, fd);
      return 0;
   }
   else if (is_signal(event))
   {
      entry = &ev->fd_table[entry_index];
      ret = entry->callbacks[event].signal(ev->data, 0);
   }
   else
   {
      entry = &ev->fd_table[entry_index];
      ret = entry->callbacks[event].io(ev->data, res_fd, ret, buf, buf_len);
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
fd_table_lookup(struct ev *io, int fd)
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