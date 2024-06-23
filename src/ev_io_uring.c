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

static struct ev_config ctx = { 0 };
static int signal_fd;
static int running;

#define CLOSE_FD          1 << 1
#define REPLENISH_BUFFERS 1 << 2

io_handler handlers[] =
{
   [ACCEPT] = accept_handler,
   [RECEIVE] = receive_handler,
   [SEND] = send_handler,
   [CONNECT] = connect_handler,
   [SOCKET] = socket_handler,
   [SIGNAL] = signal_handler,
   [PERIODIC] = periodic_handler,
};

const int events_nr = (sizeof(handlers) / sizeof(io_handler));

/**
 * Event Handling Interface
 *  1. ev_init: Init the event handling context
 *  2. {signal|periodic|io}_init: returns an fd
 *  3. ev_register_{signal|periodic|io}: registers the file descriptor
 */

/**
 * EV Context
 */


int
ev_setup(struct ev_setup_opts opts)
{
   int ret;

   /* set opts */

   ctx.napi = opts.napi;
   ctx.sqpoll = opts.sqpoll;
   ctx.use_huge = opts.use_huge;
   ctx.defer_tw = opts.defer_tw;
   ctx.snd_ring = opts.snd_ring;
   ctx.snd_bundle = opts.snd_bundle;
   ctx.fixed_files = opts.fixed_files;

   ctx.buf_count = opts.buf_count;

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

   /* default optsuration */

   if (ctx.defer_tw)
   {
      ctx.params.flags |= IORING_SETUP_DEFER_TASKRUN; /* overwritten by SQPOLL */
   }
   if (ctx.sqpoll)
   {
      ctx.params.flags |= IORING_SETUP_SQPOLL;
      ctx.params.sq_thread_idle = opts.sq_thread_idle;
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

int
ev_init(struct ev** ev_out,void* data)
{
   int ret;
   struct ev* ev;

   *ev_out = calloc(1,sizeof(struct ev));
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

   for (int i = 0; i < MAX_FDS; i++)
   {
      ev->io_table[i].fd = EMPTY_FD;
   }

   ev->data = data;

   sigemptyset(&ev->sigset);

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
   running = true;
   while (running)
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
ev_cleanup(struct ev* ev)
{
   if (ev)
   {
      io_uring_queue_exit(&ev->ring);
      if (ev->in_br.buf)
      {
         free(ev->in_br.buf);
      }
      free(ev);
   }
   return 0;
}

/*
 * I/O Events
 */

int
io_init(struct ev* ev, int fd, int event, io_cb cb, void* buf, size_t buf_len)
{
   int ret = 0;
   int t_index = -1;
   int domain;
   struct io_uring_sqe* sqe = get_sqe(ev);
   struct io_entry* entry = NULL;
   union sockaddr_u* addr;

   if (event >= IO_EVENTS_NR)
   {
      fprintf(stderr, "io_init: invalid event flag number: %d\n", event);
      return 1;
   }

   t_index = io_table_insert(ev, fd, cb, event);
   if (t_index < 0)
   {
      fprintf(stderr, "io_init: io_table_insert\n");
      return 1;
   }

   switch (event)
   {

      case ACCEPT:
         encode_user_data(sqe, ACCEPT, ev->id, ev->bid, fd, t_index);
         io_uring_prep_multishot_accept(sqe, fd, NULL, NULL, 0);
         break;

      case RECEIVE:
         prepare_receive(ev, fd);
         io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
         encode_user_data(sqe, RECEIVE, ev->id, 0, fd, t_index);
         sqe->flags |= IOSQE_BUFFER_SELECT;
         sqe->buf_group = 0;
         break;

      case SEND:
         io_uring_prep_send(sqe, fd, buf, buf_len, MSG_WAITALL | MSG_NOSIGNAL); /* TODO: why these flags? */
         encode_user_data(sqe, SEND, ev->id, 0, fd, t_index);
         break;

      case CONNECT:
         addr = (union sockaddr_u*)buf;
         /* expects addr to be set correctly */
         if (ctx.ipv6)
         {
            io_uring_prep_connect(sqe, fd, (struct sockaddr*) &addr->addr6, sizeof(struct sockaddr_in6));
         }
         else
         {
            io_uring_prep_connect(sqe, fd, (struct sockaddr*) &addr->addr4, sizeof(struct sockaddr_in));
         }
         encode_user_data(sqe, CONNECT, ev->id, 0, fd, t_index);
         break;

      case SOCKET:
         if (ctx.ipv6)
         {
            domain = AF_INET6;
         }
         else
         {
            domain = AF_INET;
         }
         io_uring_prep_socket(sqe, domain, SOCK_STREAM, 0, 0);     /* TODO: WHAT CAN BE USED HERE ? */
         encode_user_data(sqe, SOCKET, ev->id, 0, 0, 0);
         break;

      default:
         fprintf(stderr, "io_init: unknown event type: %d\n", event);
         return 1;
   }

   return 0;
}

int
io_accept_init(struct ev* ev, int fd, io_cb cb)
{
   return io_init(ev, fd, ACCEPT, cb, NULL, 0);
}

int
io_send_init(struct ev* ev, int fd, io_cb cb, void* buf, int buf_len)
{
   return io_init(ev, fd, SEND, cb, buf, buf_len);
}

int
io_receive_init(struct ev* ev, int fd, io_cb cb)
{
   return io_init(ev, fd, SEND, cb, NULL, 0);
}

int
io_connect_init(struct ev* ev, int fd, io_cb cb, union sockaddr_u* addr)
{
   return io_init(ev, fd, SEND, cb, (void*)addr, 0);
}

int
io_table_insert(struct ev* ev, int fd, io_cb cb, int event)
{
   int i;
   const int io_table_size = sizeof(ev->io_table) / sizeof(struct io_entry);

   /* if fd is already registered, add cb to fd entry */
   for (i = 0; i < io_table_size; i++)
   {
      if (ev->io_table[i].fd == EMPTY_FD)
      {
         break; /* stop looking once reach unregistered entries */
      }
      if (ev->io_table[i].fd == fd)
      {
         ev->io_table[i].fd = fd;
         ev->io_table[i].cbs[event] = cb;

         return i;
      }
   }

   if (ev->io_count >= io_table_size)
   {
      fprintf(stderr, "periodic_table_insert: ev->periodic_count >= periodic_table_size\n");
      return -1;
   }

   i = ev->io_count++;

   ev->io_table[i].fd = fd;
   ev->io_table[i].cbs[event] = cb;

   return i;
}

/*
 * Signal Events
 */

int
signal_init(struct ev* ev, int signum, signal_cb cb)
{
   int ret;

   /* register signal */
   ret = signal_table_insert(ev, signum, cb);
   if (ret)
   {
      fprintf(stderr, "signal_init: signal_table_insert\n");
      return 1;
   }

   /* prepare signal */
   sigaddset(&ev->sigset, signum);

   ret = sigprocmask(SIG_BLOCK, &ev->sigset, NULL);
   if (ret == -1)
   {
      fprintf(stdout, "sigprocmask\n");
      return 1;
   }

   return 0;
}

int
signal_table_insert(struct ev* ev, int signum, signal_cb cb)
{
   int i;
   const int signal_table_size = sizeof(ev->sig_table) / sizeof(struct signal_entry);
   if (ev->signal_count >= signal_table_size)
   {
      fprintf(stderr, "signal_table_insert: ev->signal_count >= signal_table_size\n");
      return 1;
   }

   i = ev->signal_count++;
   ev->sig_table[i].signum = signum;
   ev->sig_table[i].cb = cb;

   return 0;
}

int
signal_init_epoll(struct ev* ev, int signum, signal_cb cb)
{
   int ret;
   int fd;

   sigaddset(&ev->sigset, signum);

   ret = sigprocmask(SIG_BLOCK, &ev->sigset, NULL);
   if (ret == -1)
   {
      fprintf(stdout, "signal_init_epoll: sigprocmask\n");
      return -1;
   }

   fd = signalfd(-1, &ev->sigset, 0);  /* TODO: SFD_NONBLOCK | SFD_CLOEXEC Flags? */
   if (fd == -1)
   {
      perror("signal_init_epoll: signalfd");
      return -1;
   }

   return fd;
}

int
handle_signal(struct ev* ev, int t_index)
{
   if (t_index < 0 || t_index >= ev->signal_count)
   {
      fprintf(stderr, "signal_table_insert: (t_index < 0 || t_index >= ev->signal_count). t_index: %d\n", t_index);
      return 1;
   }

   return ev->sig_table[t_index].cb(ev->data, 0);
}


/**
 * Periodic Events
 */

int
periodic_init(struct ev* ev, int msec, periodic_cb cb)
{
   /* register */
   struct __kernel_timespec ts = {
      .tv_sec = msec / 1000,
      .tv_nsec = (msec % 1000) * 1000000
   };
   int t_ind = periodic_table_insert(ev, ts, cb);

   /* prepare periodic */
   struct io_uring_sqe* sqe = io_uring_get_sqe(&ev->ring);
   encode_user_data(sqe, PERIODIC, 0, 0, t_ind, t_ind);
   io_uring_prep_timeout(sqe, &ts, 0, IORING_TIMEOUT_MULTISHOT);
   ev->periodic_count++;

   return 0;
}

int
periodic_table_insert(struct ev* ev, struct __kernel_timespec ts, periodic_cb cb)
{
   int i;
   const int periodic_table_size = sizeof(ev->per_table) / sizeof(struct periodic_entry);

   if (ev->periodic_count >= periodic_table_size)
   {
      fprintf(stderr, "periodic_table_insert: ev->periodic_count >= periodic_table_size\n");
      return 1;
   }

   i = ev->periodic_count++;

   ev->per_table[i].ts.tv_sec = ts.tv_sec;
   ev->per_table[i].ts.tv_nsec = ts.tv_nsec;
   ev->per_table[i].cb = cb;

   return 0;
}

int
periodic_init_epoll(struct ev* ev, double interval)
{
   int ret;
   int fd;
   struct itimerspec new_value;
   memset(&new_value, 0, sizeof(struct itimerspec));

   fd = timerfd_create(CLOCK_MONOTONIC, 0);
   if (fd == -1)
   {
      perror("timerfd_create\n");
      return 1;
   }

   new_value.it_interval.tv_sec = (int)interval;
   new_value.it_interval.tv_nsec = (interval - (int)interval) * 1e9;
   new_value.it_value.tv_sec = (int)interval;
   new_value.it_value.tv_nsec = (interval - (int)interval) * 1e9;

   if (timerfd_settime(fd, 0, &new_value, NULL) == -1)
   {
      perror("timerfd_settime");
      return -1;
   }

   return fd;
}

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

//
//int
//prepare_read(struct ev* ev,int fd,int op)
//{
//   struct io_uring_sqe* sqe = io_get_sqe(ev);
//   io_uring_prep_read(sqe,fd,&ev->expirations,sizeof(ev->expirations),0);
//   encode_user_data(sqe,op,ev->id,ev->bid,fd,fd);
//   return 0;
//}
//
//int
//prepare_connect(struct ev* ev,int fd,union sockaddr_u addr)
//{
//   int ret;
//   struct io_uring_sqe* sqe = io_get_sqe(ev);
//
//   /* expects addr to be set correctly */
//
//   if (ctx.ipv6)
//   {
//      io_uring_prep_connect(sqe,fd,(struct sockaddr*) &addr.addr6,sizeof(struct sockaddr_in6));
//   }
//   else
//   {
//      io_uring_prep_connect(sqe,fd,(struct sockaddr*) &addr.addr4,sizeof(struct sockaddr_in));
//   }
//
//   encode_user_data(sqe,CONNECT,ev->id,0,fd, fd);
//
//   return 0;
//}
//
//int
//prepare_socket(struct ev* ev, char* host)
//{
//   struct io_uring_sqe* sqe = io_get_sqe(ev);
//   int domain;
//   if (ctx.ipv6)
//   {
//      domain = AF_INET6;
//   }
//   else
//   {
//      domain = AF_INET;
//   }
//   io_uring_prep_socket(sqe,domain,SOCK_STREAM,0,0);     /* TODO: WHAT CAN BE USED HERE ? */
//   encode_user_data(sqe,SOCKET,ev->id,0,0,0);
//   return 0;
//}
//int
//prepare_accept(struct ev* ev, int fd)
//{
//   struct io_uring_sqe* sqe = io_get_sqe(ev);
//   encode_user_data(sqe, ACCEPT, ev->id, ev->bid, fd, fd);
//   io_uring_prep_multishot_accept(sqe, fd, NULL, NULL, 0);
//   return 0;
//}
//
//int
//prepare_receive(struct ev* io, int fd)
//{
//   int ret;
//   struct io_uring_sqe* sqe = io_get_sqe(io);
//   io_uring_prep_recv_multishot(sqe, fd, NULL, 0, 0);
////   encode_user_data(sqe, RECEIVE, io->id, 0, fd);  /* TODO: fix or delete */
//   sqe->flags |= IOSQE_BUFFER_SELECT;
//   sqe->buf_group = 0;
//   return 0;
//}
//
//int
//prepare_send(struct ev* io, int fd, void* buf, size_t data_len)
//{
//   int ret;
//   struct io_uring_sqe* sqe = io_get_sqe(io);
//   io_uring_prep_send(sqe, fd, buf, data_len, MSG_WAITALL | MSG_NOSIGNAL); /* TODO: why these flags? */
////   encode_user_data(sqe, SEND, io->id, 0, fd); /* TODO: fix or delete */
//   return 0;
//}
//handle_socket(struct ev* ev,struct io_uring_cqe* cqe)
//{
//   return 1;
//}

struct io_uring_sqe*
get_sqe(struct ev* ev)
{
   struct io_uring* ring = &ev->ring;
   struct io_uring_sqe* sqe;
   do /* necessary if SQPOLL ? */
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

/**
 * Handlers
 */

int
io_setup_buffers(struct ev* ev)
{
   int ret;
   void* ptr;

   ret = io_setup_buffer_ring(ev);

   struct io_buf_ring* cbr = &ev->in_br;

   if (ctx.use_huge)
   {
      fprintf(stderr, "io_setup_buffers: use_huge not implemented yet\n"); /* TODO */
   }
   if (posix_memalign(&cbr->buf, ALIGNMENT, ctx.buf_count * ctx.buf_size))
   {
      perror("io_setup_buffer_ring: posix_memalign");
      return 1;
   }

   cbr->br = io_uring_setup_buf_ring(&ev->ring, ctx.buf_count, 0, 0, &ret);
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

   ev->bid = 0;
   return ret;
}

int
io_setup_buffer_ring(struct ev* ev)
{
   int ret;

   return 0;
}

/************ HANDLERS
 *
 */

int
io_accept_handler(struct ev* ev, struct io_uring_cqe* cqe, void** buf, int* bid)
{
   return 0;
}

int
connect_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int*)
{
   return 0;
}

int
io_receive_handler(struct ev* ev, struct io_uring_cqe* cqe, void** send_buf_base, int* bid)
{
   struct io_buf_ring* in_br = &ev->in_br;
   *send_buf_base = (void*) (in_br->buf + *bid * ctx.buf_size);
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

   /* If the size of the buffer (this_bytes) is greater than the size of the received bytes, then continue.
    * Otherwise, we iterate over another buffer
    */
   while (in_bytes)
   {
      buf = &(in_br->br->bufs[*bid]);
      data = (char*) buf->addr;
      this_bytes = buf->len;
      /** Break if the received bytes is smaller than buffer length.
       * Otherwise, continue iterating over the buffers.
       */
      if (this_bytes > in_bytes)
      {
         this_bytes = in_bytes;
      }

      in_bytes -= this_bytes;

      *bid = (*bid + 1) & (ctx.buf_count - 1);
      nr_packets++;
   }

   io_uring_buf_ring_advance(in_br->br, 1);

   return 0;
}

int
send_handler(struct ev* ev, struct io_uring_cqe* cqe, void** buf, int* bid)
{
   int ret;
   int fd;

   /* replenish buffer */
   io_uring_buf_ring_add(ev->in_br.br, *buf, ctx.buf_size, *bid, ctx.br_mask, 1);

   return 0;
}

int
socket_handler(struct ev* ev, struct io_uring_cqe* cqe, void** buf, int* bid)
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
   return (e == PERIODIC);
}

bool
is_periodic(int e)
{
   return (e == PERIODIC);
}

bool
is_signal(int e)
{
   return (e == SIGNAL);
}

int
handle_event(struct ev* ev,struct io_uring_cqe* cqe)
{
   int fd = -1;
   int res_fd = -1;
   int event = -1;
   int ret = 0;
   int entry_index = -1;
   void* buf = NULL;
   io_handler handler;
   struct fd_entry* entry = NULL;
   struct __kernel_timespec* ts_entry = NULL;

   struct user_data ud = decode_user_data(cqe);
   event = ud.event;
   fd = ud.fd;

   if (event < 0 || event >= events_nr)
   {
      fprintf(stderr,"handle_event: event \n");
      return 1;
   }

   handler = handlers[event];
   if (!handler)
   {
      fprintf(stderr,"io_handle_event: handler does not exist for event %d\n",event);
      return 1;
   }

   int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
   int bid_start = bid;
   int bid_end = bid;

   entry_index = fd_table_lookup(ev,fd);
   if (entry_index < 0)
   {
      fprintf(stderr,"io_handle_event\n");
      return 1;
   }

   ret = handler(ev,cqe,&buf,&bid_end);

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
      io_prepare_send(ev,fd,buf,cqe->res);

      io_prepare_receive(ev,fd);
      return 0;
   }
   else if (ret)
   {
      fprintf(stderr,"io_handle_event: handler error\n");
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
   if (event == ACCEPT)
   {
      res_fd = cqe->res;
   }

   int buf_len;
   if (event == RECEIVE)
   {
      buf_len = cqe->res;
   }

   if (is_periodic(event))
   {
      ts_entry = &ev->ts[entry_index];
      ret = entry->callbacks[event].periodic(ev->data,0);
      if (ret)
      {
         fprintf(stderr,"handle_event: callback[event].periodic\n");
         return 1;
      }

      /* if is_periodic2 rearm periodic and exit */
//      prepare_periodic(ev, fd);
      return 0;
   }
   else if (is_signal(event))
   {
      entry = &ev->fd_table[entry_index];
      ret = entry->callbacks[event].signal(ev->data,0);
   }
   else
   {
      entry = &ev->fd_table[entry_index];
      ret = entry->callbacks[event].io(ev->data,res_fd,ret,buf,buf_len);
   }

   if (buf)
   {
      /* replenish buffers */
      for (int i = bid_start; i != bid_end; i = (i + 1) & (ctx.buf_count - 1))
      {
         io_uring_buf_ring_add(ev->in_br.br,(void*)ev->in_br.br->bufs[bid].addr,ctx.buf_size,bid,ctx.br_mask,0);
      }
      io_uring_buf_ring_advance(ev->in_br.br,count);
   }

   return ret;
}

int
fd_table_lookup(struct ev* io,int fd)
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
   fprintf(stderr,"io_table_lookup\n");
   return -1;
}

/**
 * io_uring utils
 */

void
encode_user_data(struct io_uring_sqe* sqe,uint8_t event,uint16_t id,uint16_t bid,uint16_t fd,uint16_t ind)
{
   struct user_data ud = {
      .event = event,
      .id = id,
      .bid = bid,
      .fd = fd,
      .ind = ind,
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
   return ud.event;
}

int
io_cqe_to_bid(struct io_uring_cqe* cqe)
{
   struct user_data ud = { .as_u64 = cqe->user_data };
   return ud.bid;
}
