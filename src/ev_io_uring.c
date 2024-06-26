/* ev_io_uring.c
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 *
 * This code is based on: https://git.kernel.dk/cgit/liburing/tree/examples/proxy.c
 * (C) 2024 Jens Axboe <axboe@kernel.dk>
 *
 */

/* ev */
#include "../include/ev.h"

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

//static struct ev_config conf = { 0 }; /* TODO: no need to be global anymore, it's directly associated with context */

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
ev_setup(struct ev_config* conf, struct ev_setup_opts opts)
{
   int ret;

   /* configuration invariant asserts */
   struct user_data ud;
   size_t ud_ind_max_value = sizeof(ud.ind) * 8;
   if (MAX_SIGNALS > ud_ind_max_value || MAX_FDS > ud_ind_max_value || MAX_PERIODIC > ud_ind_max_value)
   {
      fprintf(stderr, "ev_setup: Bad configuration for MAX_SIGNALS, MAX_FDS or MAX_PERIODIC\n");
      exit(EXIT_FAILURE);
   }

   /* set opts */

   conf->napi = opts.napi;
   conf->sqpoll = opts.sqpoll;
   conf->use_huge = opts.use_huge;
   conf->defer_tw = opts.defer_tw;
   conf->snd_ring = opts.snd_ring;
   conf->snd_bundle = opts.snd_bundle;
   conf->fixed_files = opts.fixed_files;

   conf->buf_count = opts.buf_count;

   if (conf->defer_tw && conf->sqpoll)
   {
      fprintf(stderr, "Cannot use DEFER_TW and SQPOLL at the same time\n");
      exit(1);
   }

   /* setup params TODO: pull from opts */

   conf->entries = (1 << 10);
   conf->params.cq_entries = (1 << 10);
   conf->params.flags = 0;
   conf->params.flags |= IORING_SETUP_SINGLE_ISSUER; /* TODO: makes sense for pgagroal? */
   conf->params.flags |= IORING_SETUP_CLAMP;
   conf->params.flags |= IORING_SETUP_CQSIZE;
   conf->params.flags |= IORING_SETUP_DEFER_TASKRUN;

   /* default optsuration */

   if (conf->defer_tw)
   {
      conf->params.flags |= IORING_SETUP_DEFER_TASKRUN; /* overwritten by SQPOLL */
   }
   if (conf->sqpoll)
   {
      conf->params.flags |= IORING_SETUP_SQPOLL;
      conf->params.sq_thread_idle = opts.sq_thread_idle;
   }
   if (!conf->sqpoll && !conf->defer_tw)
   {
      conf->params.flags |= IORING_SETUP_COOP_TASKRUN;
   }
   if (!conf->buf_count)
   {
      conf->buf_count = BUFFER_COUNT;
   }
   if (!conf->buf_size)
   {
      conf->buf_size = BUFFER_SIZE;
   }
   conf->br_mask = (conf->buf_count - 1);

   if (conf->fixed_files)
   {
      fprintf(stderr, "io_context_setup: no support for fixed files\n"); /* TODO */
      exit(1);
   }

   return 0;
}

int
ev_init(struct ev** ev_out, void* data, struct ev_setup_opts opts)
{
   int ret;
   struct ev* ev;
   struct ev_config conf;

   *ev_out = calloc(1, sizeof(struct ev));
   if (!*ev_out)
   {
      fprintf(stderr, "ev_init: calloc\n");
      return 1;
   }

   ev = *ev_out;

   ret = ev_setup(&ev->conf, opts);
   if (ret)
   {
      fprintf(stderr, "ev_init: ev_setup\n");
      return 1;
   }

   conf = ev->conf;

   ret = io_uring_queue_init_params(conf.entries, &ev->ring, &conf.params);
   if (ret)
   {
      fprintf(stderr, "ev_init: io_uring_queue_init_params: %s\n", strerror(-ret));
      fprintf(stderr, "make sure to setup context with io_context_setup\n");
      return 1;
   }

   ret = ev_setup_buffers(ev);
   if (ret)
   {
      fprintf(stderr, "ev_init: ev_setup_buffers");
      return 1;
   }

   for (int i = 0; i < MAX_FDS; i++)
   {
      ev->io_table[i].fd = EMPTY;
   }

   ev->data = data;

   sigemptyset(&ev->sigset);

   return 0;
}

int
ev_loop(struct ev* ev)
{
   int ret;
   int sig;
   int flags;
   int events;
   int to_wait = 1; /* wait for any 1 */
   unsigned int head;
   static int wait_usec = 1000000;
   struct io_uring_cqe* cqe;
   struct __kernel_timespec* ts;
   struct __kernel_timespec idle_ts = {
      .tv_sec = 0,
      .tv_nsec = 100000000LL
   };
//   struct __kernel_timespec active_ts = idle_ts;
//   if (wait_usec > 1000000)
//   {
//      active_ts.tv_sec = wait_usec / 1000000;
//      wait_usec -= active_ts.tv_sec * 1000000;
//   }
//   active_ts.tv_nsec = wait_usec * 1000;
   struct timespec timeout = {
      .tv_sec = 0,
      .tv_nsec = 0
   };

   flags = 0;
   ev->running = true; /* safe to initialize */
   while (atomic_load(&ev->running))
   {
      ts = &idle_ts;
      io_uring_submit_and_wait_timeout(&ev->ring, &cqe, to_wait, ts, NULL);

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
         if (ev_handler(ev, cqe))
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

      sig = sigtimedwait(&ev->sigset, NULL, &timeout);
      if (sig > 0)
      {
         ret = signal_handler(ev, sig, sig);
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
ev_setup_buffers(struct ev* ev)
{
   int ret;
   void* ptr;
   struct ev_config conf = ev->conf;

   struct io_buf_ring* in_br = &ev->in_br;
   struct io_buf_ring* out_br = &ev->out_br;

   if (conf.use_huge)
   {
      fprintf(stderr, "ev_setup_buffers: use_huge not implemented yet\n"); /* TODO */
   }
   if (posix_memalign(&in_br->buf, ALIGNMENT, conf.buf_count * conf.buf_size))
   {
      perror("ev_setup_buffers: posix_memalign");
      return 1;
   }
   if (posix_memalign(&out_br->buf, ALIGNMENT, conf.buf_count * conf.buf_size))
   {
      perror("ev_setup_buffers: posix_memalign");
      return 1;
   }

   in_br->br = io_uring_setup_buf_ring(&ev->ring, conf.buf_count, 0, 0, &ret);
   out_br->br = io_uring_setup_buf_ring(&ev->ring, conf.buf_count, 1, 0, &ret);
   if (!in_br->br || !out_br->br)
   {
      fprintf(stderr, "Buffer ring register failed %d\n", ret);
      return 1;
   }

   ptr = in_br->buf;
   for (int i = 0; i < conf.buf_count; i++)
   {
//      printf("add bid %d, data %p\n", i, ptr);
      io_uring_buf_ring_add(in_br->br, ptr, conf.buf_size, i, conf.br_mask, i);
      ptr += conf.buf_size;
   }
   io_uring_buf_ring_advance(in_br->br, conf.buf_count);

   ptr = out_br->buf;
   for (int i = 0; i < conf.buf_count; i++)
   {
//      printf("add bid %d, data %p\n", i, ptr);
      io_uring_buf_ring_add(out_br->br, ptr, conf.buf_size, i, conf.br_mask, i);
      ptr += conf.buf_size;
   }
   io_uring_buf_ring_advance(out_br->br, conf.buf_count);

   ev->next_out_bid = 0;
   return ret;
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

int
ev_handler(struct ev* ev, struct io_uring_cqe* cqe)
{
   int ret = 0;
   struct user_data ud;
   int accept_fd = -1;
   void* buf = NULL;
   struct fd_entry* entry = NULL;
   struct __kernel_timespec* ts_entry = NULL;
   int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
   int bid_start = bid;
   int bid_end = bid;
   int buf_len;

   ud = decode_user_data(cqe);

   if (ud.event < 0 || ud.event >= EVENTS_NR)
   {
      fprintf(stderr, "handle_event: event \n");
      return 1;
   }

   if (ud.event == PERIODIC)
   {
      return periodic_handler(ev, ud.ind);
   }
   else if (ud.event == SIGNAL)
   {
      return signal_handler(ev,ud.ind,-1); /* unused, currently not handled here */
   }

   /* I/O event */
   return io_handler(ev,cqe);
}

/**
 * I/O Events
 */

/**
 * @param buf_len: either the length of the buffer or the bid.
 */
int
io_init(struct ev* ev,int fd,int event,io_cb cb,void* buf,size_t buf_len,int bid)
{
   int ret = 0;
   int t_index = -1;
   int domain;
   struct ev_config conf = ev->conf;
   struct io_uring_sqe* sqe = get_sqe(ev);
   struct io_entry* entry = NULL;
   union sockaddr_u* addr;

   if (event >= IO_EVENTS_NR)
   {
      fprintf(stderr,"io_init: invalid event flag number: %d\n",event);
      return 1;
   }

   t_index = io_table_insert(ev,fd,cb,event);
   if (t_index < 0)
   {
      fprintf(stderr,"io_init: io_table_insert\n");
      return 1;
   }

   switch (event)
   {

      case ACCEPT:
         encode_user_data(sqe,ACCEPT,ev->id,ev->bid,fd,t_index);
         io_uring_prep_multishot_accept(sqe,fd,NULL,NULL,0);
         break;

      case RECEIVE:
         io_uring_prep_recv_multishot(sqe,fd,NULL,0,0);
         encode_user_data(sqe,RECEIVE,ev->id,0,fd,t_index);
         sqe->flags |= IOSQE_BUFFER_SELECT;
         sqe->buf_group = 0;
         break;

      case SEND:
         io_uring_prep_send(sqe,fd,buf,buf_len,MSG_WAITALL | MSG_NOSIGNAL);     /* TODO: why these flags? */
         encode_user_data(sqe,SEND,ev->id,bid,fd,t_index);
         break;

      case CONNECT:
         addr = (union sockaddr_u*)buf;
         /* expects addr to be set correctly */
         if (conf.ipv6)
         {
            io_uring_prep_connect(sqe,fd,(struct sockaddr*) &addr->addr6,sizeof(struct sockaddr_in6));
         }
         else
         {
            io_uring_prep_connect(sqe,fd,(struct sockaddr*) &addr->addr4,sizeof(struct sockaddr_in));
         }
         encode_user_data(sqe,CONNECT,ev->id,0,fd,t_index);
         break;

      case SOCKET:
         if (conf.ipv6)
         {
            domain = AF_INET6;
         }
         else
         {
            domain = AF_INET;
         }
         io_uring_prep_socket(sqe,domain,SOCK_STREAM,0,0);         /* TODO: WHAT CAN BE USED HERE ? */
         encode_user_data(sqe,SOCKET,ev->id,bid,0,t_index);
         break;

      case READ: /* unused */
         io_uring_prep_read(sqe,fd,buf,buf_len,0);
         encode_user_data(sqe,SIGNAL,ev->id,bid,fd,t_index);
         break;

      default:
         fprintf(stderr,"io_init: unknown event type: %d\n",event);
         return 1;
   }

   return 0;
}

int
io_accept_init(struct ev* ev,int fd,io_cb cb)
{
   return io_init(ev,fd,ACCEPT,cb,NULL,0,-1);
}

int
io_read_init(struct ev* ev,int fd,io_cb cb)
{
   return io_init(ev,fd,READ,cb,NULL,0,-1);
}

int
io_send_init(struct ev* ev,int fd,io_cb cb,void* buf,int buf_len,int bid)
{
   return io_init(ev,fd,SEND,cb,buf,buf_len,bid);
}

int
io_receive_init(struct ev* ev,int fd,io_cb cb)
{
   return io_init(ev,fd,RECEIVE,cb,NULL,0,-1);
}

int
io_connect_init(struct ev* ev,int fd,io_cb cb,union sockaddr_u* addr)
{
   return io_init(ev,fd,CONNECT,cb,(void*)addr,0,-1);
}

int
io_table_insert(struct ev* ev,int fd,io_cb cb,int event)
{
   int i;
   const int io_table_size = sizeof(ev->io_table) / sizeof(struct io_entry);

   /* if fd is already registered, add cb to fd entry */
   for (i = 0; i < io_table_size; i++)
   {
      if (ev->io_table[i].fd == EMPTY)
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
      fprintf(stderr,"periodic_table_insert: ev->periodic_count >= periodic_table_size\n");
      return -1;
   }

   i = ev->io_count++;

   ev->io_table[i].fd = fd;
   ev->io_table[i].cbs[event] = cb;

   return i;
}

int
io_handler(struct ev* ev,struct io_uring_cqe* cqe)
{
   int ret;
   int accept_fd;
   struct user_data ud = decode_user_data(cqe);
   int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
   int bid_start = bid;
   int bid_end = bid;
   int count;
   void* buf;

   switch (ud.event)
   {
      case ACCEPT:
         return accept_handler(ev,cqe);
      case SEND:
         return send_handler(ev,cqe);
      case CONNECT:
         return connect_handler(ev,cqe);
      case RECEIVE:
      {
         ret = receive_handler(ev,cqe,&buf,&bid_end,false);
         switch (ret)
         {
            case ERROR:
               return ERROR;
            case CLOSE_FD: /* connection closed */
               close(ud.fd);
               ev->io_table[ud.ind].fd = -1; /* remove io_table entry */
               return OK;
            case REPLENISH_BUFFERS:
               printf("DEBUG - ev_handler - replenish buffers triggered\n");
               /* TODO */
               return OK;
         }
      }
   }

   return ERROR;
}

int
replenish_buffers(struct ev* ev,struct io_buf_ring* br,int bid_start,int bid_end)
{
   int count;
   struct ev_config conf = ev->conf;

   if (bid_end >= bid_start)
   {
      count = (bid_end - bid_start);
   }
   else
   {
      count = (bid_end + conf.buf_count - bid_start);
   }

   for (int i = bid_start; i != bid_end; i = (i + 1) & (conf.buf_count - 1))
   {
      io_uring_buf_ring_add(br->br,(void*)br->br->bufs[i].addr,conf.buf_size,i,conf.br_mask,0);
   }

   io_uring_buf_ring_advance(br->br,count);

   return 0;
}

/*
 * Signal Events
 */

int
signal_init(struct ev* ev,int signum,signal_cb cb)
{
   int ret;
   int t_ind;

   /* register signal */
   t_ind = signal_table_insert(ev,signum,cb);
   if (t_ind < 0)  /* TODO: t_ind serves no purpose in current implementation */
   {
      fprintf(stderr,"signal_init: signal_table_insert\n");
      return 1;
   }

   /* prepare signal */
   sigaddset(&ev->sigset,signum);

   ret = sigprocmask(SIG_BLOCK,&ev->sigset,NULL);
   if (ret == -1)
   {
      fprintf(stdout,"sigprocmask\n");
      return 1;
   }

   return 0;
}

int
signal_table_insert(struct ev* ev,int signum,signal_cb cb)
{
   int i;

   switch (signum)
   {
      case SIGTERM:
         ev->sig_table[_SIGTERM].cb = cb;
         ev->sig_table[_SIGTERM].signum = signum;
         break;
      case SIGHUP:
         ev->sig_table[_SIGHUP].cb = cb;
         ev->sig_table[_SIGHUP].signum = signum;
         break;
      case SIGINT:
         ev->sig_table[_SIGINT].cb = cb;
         ev->sig_table[_SIGINT].signum = signum;
         break;
      case SIGTRAP:
         ev->sig_table[_SIGTRAP].cb = cb;
         ev->sig_table[_SIGTRAP].signum = signum;
         break;
      case SIGABRT:
         ev->sig_table[_SIGABRT].cb = cb;
         ev->sig_table[_SIGABRT].signum = signum;
         break;
      case SIGALRM:
         ev->sig_table[_SIGALRM].cb = cb;
         ev->sig_table[_SIGALRM].signum = signum;
         break;
      default:
         fprintf(stderr,"signal not supported\n");
         return 1;
   }

   return 0;

   /* TODO: this code is kept unreachable because it is currently not possible to have the following
    *  implementation, based on signalfd
    */

   const int signal_table_size = sizeof(ev->sig_table) / sizeof(struct signal_entry);
   if (ev->signal_count >= signal_table_size)
   {
      fprintf(stderr,"signal_table_insert: ev->signal_count >= signal_table_size\n");
      return -1;
   }

   i = ev->signal_count++;
   ev->sig_table[i].signum = signum;
   ev->sig_table[i].cb = cb;

   return i;
}

int
signal_handler(struct ev* ev,int t_index,int signum)
{
   if (signum >= 0) /* currently signum is used here as a workaround, ideally there should be no signum */
   {
      switch (signum)
      {
         case SIGTERM:
            ev->sig_table[_SIGTERM].cb(ev->data,0);
            break;
         case SIGHUP:
            ev->sig_table[_SIGHUP].cb(ev->data,0);
            break;
         case SIGINT:
            ev->sig_table[_SIGINT].cb(ev->data,0);
            break;
         case SIGTRAP:
            ev->sig_table[_SIGTRAP].cb(ev->data,0);
            break;
         case SIGABRT:
            ev->sig_table[_SIGABRT].cb(ev->data,0);
            break;
         case SIGALRM:
            ev->sig_table[_SIGALRM].cb(ev->data,0);
            break;
         default:
            fprintf(stderr,"signal not supported\n");
            return 1;
      }

      return 0;
   }

   /** TODO: currently this has no solution
    *
    */
   fprintf(stderr,"shouldn't execute");
   exit(EXIT_FAILURE);

   if (t_index < 0 || t_index >= ev->signal_count)
   {
      fprintf(stderr,"signal_handler: (t_index < 0 || t_index >= ev->signal_count). t_index: %d\n",t_index);
      return 1;
   }

   return ev->sig_table[t_index].cb(ev->data,0);
}

/**
 * Periodic Events
 */

int
periodic_init(struct ev* ev,int msec,periodic_cb cb)
{
   /* register */
   struct __kernel_timespec ts = {
      .tv_sec = msec / 1000,
      .tv_nsec = (msec % 1000) * 1000000
   };
   int t_ind = periodic_table_insert(ev,ts,cb);

   /* prepare periodic */
   struct io_uring_sqe* sqe = io_uring_get_sqe(&ev->ring);
   encode_user_data(sqe,PERIODIC,0,0,t_ind,t_ind);
   io_uring_prep_timeout(sqe,&ev->per_table[t_ind].ts,0,IORING_TIMEOUT_MULTISHOT);

   return 0;
}

int
periodic_table_insert(struct ev* ev,struct __kernel_timespec ts,periodic_cb cb)
{
   int i;
   const int periodic_table_size = sizeof(ev->per_table) / sizeof(struct periodic_entry);

   if (ev->periodic_count >= periodic_table_size)
   {
      fprintf(stderr,"periodic_table_insert: ev->periodic_count >= periodic_table_size\n");
      return 1;
   }

   i = ev->periodic_count++;

   ev->per_table[i].ts.tv_sec = ts.tv_sec;
   ev->per_table[i].ts.tv_nsec = ts.tv_nsec;
   ev->per_table[i].cb = cb;

   return i;
}

int
periodic_init_epoll(struct ev* ev,double interval)
{
   int ret;
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
periodic_handler(struct ev* ev,int t_index)
{
   if (t_index < 0 || t_index >= ev->periodic_count)
   {
      fprintf(stderr,"periodic_handler: (t_index < 0 || t_index >= ev->periodic_count). t_index: %d\n",t_index);
      return 1;
   }

   return ev->per_table[t_index].cb(ev->data,0);
}

/*
 * Utils
 */

int
rearm_receive(struct ev* io,int fd,int t_index)
{
   int ret;
   struct io_uring_sqe* sqe = get_sqe(io);
   io_uring_prep_recv_multishot(sqe,fd,NULL,0,0);
   encode_user_data(sqe,RECEIVE,io->id,0,fd,t_index);
   sqe->flags |= IOSQE_BUFFER_SELECT;
   sqe->buf_group = 0;
   return 0;
}

int
prepare_send(struct ev* ev,int fd,void* buf,size_t data_len,int t_index)
{
   int ret;
   struct io_uring_sqe* sqe = get_sqe(ev);
   io_uring_prep_send(sqe,fd,buf,data_len,MSG_WAITALL | MSG_NOSIGNAL);
   encode_user_data(sqe,SEND,ev->id,0,fd,t_index);
   return 0;
}

/**
 * HANDLERS
 */

int
accept_handler(struct ev* ev,struct io_uring_cqe* cqe)
{
   int ret;
   struct user_data ud = decode_user_data(cqe);
   int accept_fd = cqe->res;
   int t_index = ud.ind;
   ret = ev->io_table[t_index].cbs[ACCEPT](ev->data,accept_fd,0,NULL,0);

   return ret;
}

int
connect_handler(struct ev* ev,struct io_uring_cqe* cqe)
{
   int ret;
   struct user_data ud = decode_user_data(cqe);
   int t_index = ud.ind;
   ret = ev->io_table[t_index].cbs[CONNECT](ev->data,ud.fd,0,NULL,0);
   return ret;
}

int
receive_handler(struct ev* ev,struct io_uring_cqe* cqe,void** send_buf_base,int* bid,bool is_proxy)
{
   int ret;
   struct ev_config conf = ev->conf;
   struct user_data ud = decode_user_data(cqe);
   struct io_buf_ring* in_br = &ev->in_br;
   struct io_buf_ring* out_br = &ev->out_br;
   *send_buf_base = (void*) (in_br->buf + *bid * conf.buf_size);
   struct io_uring_buf* buf;
   void* data;
   int pending_recv = 0;
   int this_bytes;
   int nr_packets = 0;
   int in_bytes;
   int bid_start = *bid;

   if (cqe->res == -ENOBUFS)
   {
      fprintf(stderr,"io_receive_handler: Not enough buffers\n");
      return REPLENISH_BUFFERS;
   }

   if (!(cqe->flags & IORING_CQE_F_BUFFER))
   {
      if (!(cqe->res)) /* Closed connection */
      {
         return CLOSE_FD;
      }
   }

   in_bytes = cqe->res;

   /* If the size of the buffer (this_bytes) is greater than the size of the received bytes, then continue.
    * Otherwise, we iterate over another buffer. */
   while (in_bytes)
   {
      buf = &(in_br->br->bufs[*bid]);
      data = (char*) buf->addr;
      this_bytes = buf->len;

      /* Break if the received bytes is smaller than buffer length. Otherwise, continue iterating over the buffers. */
      if (this_bytes > in_bytes)
      {
         this_bytes = in_bytes;
      }

      io_uring_buf_ring_add(out_br->br,data,this_bytes,*bid,conf.br_mask,0);
      io_uring_buf_ring_advance(out_br->br,1);

      in_bytes -= this_bytes;

      *bid = (*bid + 1) & (conf.buf_count - 1);
      nr_packets++;
   }

   /* From the docs: https://man7.org/linux/man-pages/man3/io_uring_prep_recv_multishot.3.html
    * "If a posted CQE does not have the IORING_CQE_F_MORE flag set then the multishot receive will be
    * done and the application should issue a new request."
    */
   if (!(cqe->flags & IORING_CQE_F_MORE))
   {
      ret = rearm_receive(ev,ud.fd,ud.ind);
      if (ret)
      {
         return 1;
      }
   }

   ret = replenish_buffers(ev,in_br,bid_start,*bid);
   if (ret)
   {
      return 1;
   }

   return 0;
}

int
send_handler(struct ev* ev,struct io_uring_cqe* cqe)
{
   int ret;
   int buf_len = cqe->res;
   struct ev_config conf = ev->conf;
   struct user_data ud = decode_user_data(cqe);
   if (ud.bid < 0)
   {
      return OK;
   }
   int bid_end = (ud.bid + buf_len / conf.buf_size + (int)(buf_len % conf.buf_size > 0)) % conf.buf_count;
   ret = replenish_buffers(ev,&ev->out_br,ud.bid,bid_end);
   if (ret)
   {
      return 1;
   }
   return 0;
}

int
socket_handler(struct ev* ev,struct io_uring_cqe* cqe,void** buf,int* bid)
{
   int ret;
   int fd;

   fd = cqe->res;

   /* TODO: do something cool */

   return 0;
}

/**
 * io_uring utils
 */

void
encode_user_data(struct io_uring_sqe* sqe,uint8_t event,uint16_t id,uint8_t bid,uint16_t fd,uint16_t ind)
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

struct user_data
decode_user_data(struct io_uring_cqe* cqe)
{
   struct user_data ud = { .as_u64 = cqe->user_data };
   return ud;
}

//int
//io_decode_op(struct io_uring_cqe* cqe)
//{
//   struct user_data ud = { .as_u64 = cqe->user_data };
//   return ud.event;
//}
//
//int
//io_cqe_to_bid(struct io_uring_cqe* cqe)
//{
//   struct user_data ud = { .as_u64 = cqe->user_data };
//   return ud.bid;
//}

struct io_uring_sqe*
get_sqe(struct ev* ev)
{
   struct io_uring* ring = &ev->ring;
   struct io_uring_sqe* sqe;
   do /* necessary if SQPOLL, but I don't think there is an advantage of using SQPOLL */
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

void
next_bid(struct ev* ev,int* bid)
{
   struct ev_config conf = ev->conf;
   *bid = (*bid + 1) % conf.buf_count;
}
