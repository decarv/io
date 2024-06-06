/* io.c
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 *
 * This code is based on: https://git.kernel.dk/cgit/liburing/tree/examples/proxy.c
 * (C) 2024 Jens Axboe <axboe@kernel.dk>
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

/* io lib */
#include "io.h"

static struct io_configuration ctx = {0 };

char* client_port = "8800";
char* server_port = "8801";


enum {
    ACCEPT  = 1,
    RECEIVE = 2,
    SEND    = 3,
    CONNECT = 4,
    SOCKET  = 5,
    SIGNAL  = 6,
    /* TODO: ADD SIGNALS */
};

int (*handlers[])(struct io *, struct io_uring_cqe *) =
{
   [ACCEPT]  = io_handle_accept,
   [RECEIVE] = io_handle_receive,
   [SEND]    = io_handle_send,
   [SOCKET]  = io_handle_socket,
   [CONNECT] = io_handle_connect,
   [SIGNAL]  = io_handle_signal,
};

int prepare_out_socket(struct io *conn)
{
   int ret = 0;
   int fd = -1;
   struct addrinfo hints;
   struct addrinfo *res;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;

   if ((ret = getaddrinfo("localhost", server_port, &hints, &res)) < 0)
   {
      perror("getaddrinfo\n");
      return 1;
   }

   if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
   {
      perror("socket\n");
      return 1;
   }

   if (connect(fd, res->ai_addr, res->ai_addrlen) < 0)
   {
      fprintf(stdout, "Error connecting to server");
      return 1;
   }

   io_store_fd(conn, fd);

   return 0;
}

int prepare_in_socket(struct io *conn)
{
   int optval;
   int fd = -1;
   int ret = 0;
   struct addrinfo hints;
   struct addrinfo *res;
   memset(&hints, 0, sizeof(hints));

   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_PASSIVE;

   ret = getaddrinfo(NULL, client_port, &hints, &res);
   if (ret < 0)
   {
      perror("getaddrinfo\n");
      return 1;
   }

   if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
   {
      perror("socket\n");
      return 1;
   }

   optval = 1;
   ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
   if (ret < 0)
   {
      perror("setsockopt");
      exit(EXIT_FAILURE);
   }

   ret = bind(fd, res->ai_addr, res->ai_addrlen);
   if (ret < 0)
   {
      perror("bind\n");
      return 1;
   }

   ret = listen(fd, 16);
   if (ret < 0)
   {
      perror("listen\n");
      return 1;
   }

   io_store_fd(conn, fd);

   return 0;
}

//struct io_connection*
//io_cqe_to_connection(struct io_uring_cqe *cqe)
//{
//   struct user_data ud = { .as_u64 = cqe->user_data };
//   return ctx.connections[ud.id];
//}

void
io_encode_data(struct io_uring_sqe *sqe, uint8_t op, uint16_t id, uint16_t bid, uint16_t fd)
{
   struct user_data ud = {
           .op = op,
           .id = id,
           .bid = bid,
           .fd = fd,
           .__rsv = 0,
   };
   io_uring_sqe_set_data64(sqe, ud.as_u64);
}

struct
user_data io_decode_data(struct io_uring_cqe *cqe)
{
   struct user_data ud = { .as_u64 = cqe->user_data };
   return ud;
}

int
io_decode_op(struct io_uring_cqe *cqe)
{
   struct user_data ud = { .as_u64 = cqe->user_data };
   return ud.op;
}

int
io_cqe_to_bid(struct io_uring_cqe *cqe)
{
   struct user_data ud = { .as_u64 = cqe->user_data };
   return ud.bid;
}

/**
 * Handles accept from cqe main_io then prepares a receive.
 * @param io
 * @param cqe
 * @return
 */
int
io_handle_accept(struct io *io, struct io_uring_cqe *cqe)
{
   pid_t pid;
   pid = fork();

   if (!pid) /* child */
   {
      /*
       * TODO
       *  Like other multishot type requests, the application should look at the CQE flags and see if IORING_CQE_F_MORE
       *  is set on completion as an indication of whether or not the accept request will generate further CQEs.
       *  Ref.: https://man.archlinux.org/man/extra/liburing/io_uring_prep_multishot_accept.3.en
       */
      struct io *child_io;
      io_init(&child_io);
      io_prepare_receive(child_io, cqe->res);
      io_loop(child_io);
   }
   else
   {
      printf("connection established. PID = %d\n", pid);
   }
   return 0;
}

int
io_handle_signal(struct io *io, struct io_uring_cqe *cqe)
{
   return 0;
}

int
io_handle_connect(struct io *io, struct io_uring_cqe *cqe)
{
   struct io **io_p = &io;

   return 0;
}

int
io_handle_receive(struct io *io, struct io_uring_cqe *cqe)
{
   int bid = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
   char* msg = &io->br.buf[bid];
   size_t msglen;

   /* Unused */
   struct io_buf_ring *cbr = &io->br;
   int nr_packets = 0;
   int pending_recv = 0;
   int in_bytes = cqe->res;
   struct io_uring_buf *io_buf;
   int nr_bufs = ctx.buf_count;
   int* bid_p = &bid;
   /**********/

   printf("IORING_CQE_F_MORE: %d\n", cqe->flags & IORING_CQE_F_MORE);
   if (!(cqe->flags & IORING_CQE_F_BUFFER)) {
      pending_recv = 0;

      if (!(cqe->res)) {
         fprintf(stderr, "no buffer assigned, res=%d\n", cqe->res);
         return 1;
      }
   }

   printf("Contents of io->br.buf[%d]: %s\n", bid, msg);

   return 0;
}

int
io_handle_send(struct io *io, struct io_uring_cqe *cqe)
{
   int ret;
   int fd;


   fd = cqe->res;


   return 0;
}

int
io_handle_cqe(struct io *io, struct io_uring_cqe *cqe)
{
   int ret;
   int (*handler)(struct io *, struct io_uring_cqe *);

   int op = io_decode_op(cqe);

   handler = handlers[op];
   ret = handler(io, cqe);
   if (ret)
   {
      fprintf(stderr, "handler error\n");
      return 1;
   }

   return 0;
}

int
io_prepare_connect(struct io *io, int fd, union io_sockaddr addr)
{
   int ret;
   struct io_uring_sqe *sqe = io_get_sqe(io);

   ret = io_store_fd(io, fd);
   if (ret)
   {
      fprintf(stderr, "io_prepare_connect\n");
      return 1;
   }


   /* expects addr to be set correctly */

   if (ctx.ipv6)
   {
      io_uring_prep_connect(sqe, fd, (struct sockaddr *) &addr.addr6, sizeof(struct sockaddr_in6));
   }
   else
   {
      io_uring_prep_connect(sqe, fd, (struct sockaddr *) &addr.addr4, sizeof(struct sockaddr_in));
   }

   io_encode_data(sqe, CONNECT, io->id, 0, fd);

   return 0;
}

int
io_prepare_socket(struct io *io)
{
   struct io_uring_sqe *sqe = io_get_sqe(io);
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
io_handle_socket(struct io *io, struct io_uring_cqe *cqe)
{
   return 1;
//   int ret;
//   int socket;
//   int fd;
//   struct io_uring_sqe *sqe;
//   struct user_data ud = io_decode_data(cqe);
//
//   int port = 8888;
//
//   fd = cqe->res;
//
//   if (ctx.ipv6)
//   {
//      memset(&c->addr6, 0, sizeof(c->addr6));
//      c->addr6.sin6_family = AF_INET6;
//      c->addr6.sin6_port = htons(port);
//      ret = inet_pton(AF_INET6, "localhost", &c->addr6.sin6_addr);
//   }
//   else
//   {
//      memset(&c->addr, 0, sizeof(c->addr));
//      c->addr.sin_family = AF_INET;
//      c->addr.sin_port = htons(send_port);
//      ret = inet_pton(AF_INET, host, &c->addr.sin_addr);
//   }
//   if (ret <= 0) {
//      if (!ret)
//         fprintf(stderr, "host not in right format\n");
//      else
//         perror("inet_pton");
//      return 1;
//   }
//
//   io_connection_register_fd(io, fd);
//
//   sqe = get_sqe(ring);
//   if (ipv6) {
//      io_uring_prep_connect(sqe, c->out_fd,
//                            (struct sockaddr *) &c->addr6,
//                            sizeof(c->addr6));
//   } else {
//      io_uring_prep_connect(sqe, c->out_fd,
//                            (struct sockaddr *) &c->addr,
//                            sizeof(c->addr));
//   }
//   encode_userdata(sqe, c, __CONNECT, 0, c->out_fd);
//   return 0;
}


int
io_init(struct io **io)
{
   int ret;

   if (*io)
   {
      fprintf(stderr, "io_init: io is a non-null pointer\n");
      return 1;
   }

   *io = calloc(1, sizeof(struct io));

   ret = io_uring_queue_init_params(ctx.entries, &(*io)->ring, &ctx.params);
   if (ret)
   {
      fprintf(stderr, "io_init: io_uring_queue_init_params: %s\n", strerror(-ret));
      return 1;
   }

   memset((*io)->fd, -1, FDS);

   io_setup_buffers(*io);

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
      ctx.buf_count = BUFFER_POOL_SIZE;
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

struct io_uring_sqe *io_get_sqe(struct io *io)
{
   struct io_uring *ring = &io->ring;
   struct io_uring_sqe *sqe;
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
   } while (1);
}

int
io_prepare_accept(struct io *io, int fd)
{
   struct io_uring_sqe *sqe = io_get_sqe(io);
//   if (fd < 0)
//   {
//      fprintf(stderr, "io_prepare_accept: io_get_next_fd\n");
//      exit(1);
//   }

   io_encode_data(sqe, ACCEPT, io->id, io->bid, fd);

   io_uring_prep_multishot_accept(sqe, fd, NULL, NULL, 0);

   return 0;
}

void
next_bid(int *bid)
{
   *bid = ( *bid + 1 ) % ctx.buf_count;
}

int
io_prepare_receive(struct io *io, int fd)
{
   int ret;
   struct io_uring_sqe *sqe = io_get_sqe(io);
   int bid = 0;
//   next_bid(&io->bid);

   io_uring_prep_recv_multishot(sqe,
                                fd,
                                NULL,
                                0,
                                0);

   io_encode_data(sqe,
                  RECEIVE,
                  io->id,
                  0,
                  fd);

   sqe->flags |= IOSQE_BUFFER_SELECT;
   sqe->buf_group = 0;

   return 0;
}


int
io_prepare_send(struct io *io, int fd, char *data)
{
   int res;
   size_t data_len;
   struct io_uring_sqe *sqe = io_get_sqe(io);

   io_store_fd(io, fd);

   if (!data)
   {
      data_len = 0;
   }
   else
   {
      data_len = strnlen(data, LENGTH);
   }

   io_uring_prep_send(sqe, fd, data, data_len, MSG_WAITALL | MSG_NOSIGNAL); /* TODO: why these flags? */

   io_encode_data(sqe, SEND, io->id, 0, fd);

   io_uring_prep_send(sqe, fd, &io->br, ctx.buf_size, 0);

   return 0;
}

int
io_start(struct io* main_io, int listening_socket)
{
   /* TODO[1]: setup signals to follow up */
   /* TODO[2]: implement fixed_files opt */
   io_uring_queue_init_params(ctx.entries, &main_io->ring, &ctx.params);
   io_prepare_accept(main_io, listening_socket);
   io_loop(main_io);

   return 0;
}

int
io_loop(struct io *io) {
   struct __kernel_timespec active_ts, idle_ts;
   int flags;
   static int wait_usec = 1000000;
   idle_ts.tv_sec = 0;
   idle_ts.tv_nsec = 100000000LL;
   active_ts = idle_ts;
   if (wait_usec > 1000000) {
      active_ts.tv_sec = wait_usec / 1000000;
      wait_usec -= active_ts.tv_sec * 1000000;
   }
   active_ts.tv_nsec = wait_usec * 1000;

   flags = 0;
   while (1) {
      struct __kernel_timespec *ts = &idle_ts;
      struct io_uring_cqe *cqe;
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
         printf("%d\n", cqe->res);
         if (io_handle_cqe(io, cqe))
         {
            fprintf(stderr, "io_handle_cqe\n");
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

/**
 * TODO: Assess the best size of the buffer rings
 * based on empty buffer rings and consumption speed.
 */
int
io_setup_buffers(struct io *io)
{
   int ret;
   ret = io_setup_buffer_ring(io);

   struct io_buf_ring *cbr = &io->br;

   if (ctx.use_huge)
   {
      fprintf(stderr, "io_setup_buffers: use_huge not implemented yet\n"); /* TODO */
   }
   if (posix_memalign(&cbr->buf, ALIGNMENT,
                      ctx.buf_size))
   {
      perror("io_setup_buffer_ring: posix_memalign");
      return 1;
   }

//  TODO
//   br_ptr = (void *) cbr->br;
//   for (int bid = 0; bid < ctx->br_count; bid++) {
//      /* Assign br_ptr with the addr/len/buffer_id supplied.
//       * I will be able to retrieve this by bid after. */
//      io_uring_buf_ring_add(br_ptr,
//                            cbr->buf,
//                            ctx->br_size,
//                            bid,
//                            ctx->br_mask,
//                            bid);
//      br_ptr += ctx->br_size;
//   }
//   io_uring_buf_ring_advance(cbr->br, ctx->br_count);

   cbr->br = io_uring_setup_buf_ring(&io->ring, ctx.buf_count, 0, 0, &ret);
   if (!cbr->br)
   {
      fprintf(stderr, "Buffer ring register failed %d\n", ret);
      return 1;
   }

   void* ptr = cbr->buf;
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
io_setup_buffer_ring(struct io *io)
{
   int ret;

   return 0;
}

int
io_store_fd(struct io *io, int fd)
{
   if (io->fd_count >= FDS)
   {
      fprintf(stderr, "io_connection_get_fd: io->fd_count >= FDS\n");
      return -1;
   }
   return io->fd[io->fd_count++] = fd;
}