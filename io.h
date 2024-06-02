/* io.h
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 *
 * TODO:
 *  - Dump the transfered bytes to console;
 *  - Connect to server
 *
 * This code is based on: https://git.kernel.dk/cgit/liburing/tree/examples/proxy.c
 * (C) 2024 Jens Axboe <axboe@kernel.dk>
 */

#include <sys/eventfd.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <liburing.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <err.h>
#include <sys/mman.h>

#define USE_PARAMS (1 << 0)
#define USE_MEM (1 << 1)

#define ALIGNMENT sysconf(_SC_PAGESIZE)
/* BUFFER_SIZE == 4k */
#define BUFFER_SIZE (1 << 12)
#define BUFFER_POOL_SIZE 4

#define CONNECTIONS 100
#define MAX_HANDLERS 32


/* Struct Definitions */


struct io_context
{
   int entries;
   struct io_connection *connections[CONNECTIONS];

   /* ring mapped buffers */
   int br_size;
   int br_count;
   size_t buffer_ring_size;
   struct io_uring_buf_ring *buffer_rings;
   uint8_t* buffer_base;  /* apparently the buffer starts after the buffer_rings */

   struct io_uring_params params;
   struct io_uring_buf *buf_pool;
   int br_mask;

   struct io_uring_buf buf;  // TODO: confirm this is struct io_uring_buf
   size_t buf_size;

   struct io_connection *main_io;

   atomic_int current_bgid;
   int (*handlers[MAX_HANDLERS])(struct io_context *, struct io_connection *, struct io_uring_cqe *);
};

struct io_connection_buf_ring {
    struct io_uring_buf_ring *br;
    void *buf;
    int bgid;
};

struct io_connection {

   int id;

   int out_fd;
   int in_fd;

   struct io_uring ring;
   struct io_uring_sqe *sqe;
   struct io_uring_cqe *cqe;

   /* iovecs */
   int iovecs_nr;
   struct iovec *iovecs;

   /* buffer ring */
   struct io_connection_buf_ring in_br;
   struct io_connection_buf_ring out_br;

   int (*handlers[MAX_HANDLERS])(struct io_context *, struct io_connection *, struct io_uring_cqe *);
};

struct user_data {
    union {
        struct {
            uint8_t op;
            uint16_t id;
            uint16_t buffer_id;
            uint16_t fd;
            uint8_t __rsv;
        };
        uint64_t as_u64;
    };
};

/* Function Definitions */

struct io_connection*
io_cqe_to_connection(struct io_uring_cqe *cqe);
int
io_prepare_accept(struct io_connection *io);
int
io_prepare_receive(struct io_connection *io);
int
io_prepare_send(struct io_connection *io);
int
io_connection_init(struct io_connection **io);
int
io_handle_accept(struct io_connection *io, struct io_uring_cqe *cqe);
int
io_handle_send(struct io_connection *io, struct io_uring_cqe *cqe);
int
io_handle_receive(struct io_connection *io, struct io_uring_cqe *cqe);
int
io_loop(struct io_connection *io);
void
io_encode_data(struct io_uring_sqe *sqe, uint8_t op, uint16_t id, uint16_t buffer_id, uint16_t fd);
struct
user_data io_decode_data(struct io_uring_cqe *cqe);
int
io_recv_ring_setup(struct io_connection *io);
int
io_setup_send_ring(struct io_connection *io);
int
io_setup_buffer_rings(struct io_connection *io);


/* Constants Declarations */

static struct io_context *io_ctx = NULL;
char* client_port = "8800";
char* server_port = "8801";


bool sqpoll = true;
bool defer_tw = false;
bool snd_ring = false;
bool snd_bundle = false;
bool fixed_files = false;
bool napi = false;
bool use_huge = false;

enum {
    ACCEPT  = 1,
    RECEIVE = 2,
    SEND    = 3,
};

int (*handlers[])(struct io_connection *, struct io_uring_cqe *) =
{
   [ACCEPT]  = io_handle_accept,
   [RECEIVE] = io_handle_receive,
   [SEND]    = io_handle_send,
};

/* Function Declarations */

int prepare_out_socket(struct io_connection *conn)
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

   conn->out_fd = fd;

   return 0;
}

int prepare_in_socket(struct io_connection *conn)
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

   conn->in_fd = fd;

   return 0;
}

struct io_connection*
io_cqe_to_connection(struct io_uring_cqe *cqe)
{
   struct user_data ud = { .as_u64 = cqe->user_data };
   return io_ctx->connections[ud.id];
}

void
io_encode_data(struct io_uring_sqe *sqe, uint8_t op, uint16_t id, uint16_t buffer_id, uint16_t fd)
{
   struct user_data ud = {
           .op = op,
           .id = id,
           .buffer_id = buffer_id,
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
io_handle_accept(struct io_connection *io, struct io_uring_cqe *cqe)
{
   struct io_connection **io_p = &io;
   pid_t pid;
   /* child */
   pid = fork();
   if (!pid)
   {
      io_connection_init(io_p);
      io->out_fd = cqe->res;
      io->in_fd = cqe->res;  /* TODO: if its supposed to act as a proxy, than this should be changed */
      io_prepare_receive(io);
      io_loop(io);
   }
   else
   {
      printf("connection established. PID = %d\n", pid);
   }
   return 0;
}

int
io_handle_receive(struct io_connection *io, struct io_uring_cqe *cqe)
{
   printf("cqe->res: %d\n", cqe->res);
   io_prepare_send(io);
   return 0;
}

int
io_handle_send(struct io_connection *io, struct io_uring_cqe *cqe)
{
   printf("send\n");
   return 0;
}

int
io_handle_cqe(struct io_connection *io, struct io_uring_cqe *cqe)
{
   int ret;
   int (*handler)(struct io_connection *, struct io_uring_cqe *);

   int op = io_decode_op(cqe);

   /* TODO: Inspect array out of bounds */
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
io_connection_init(struct io_connection **io)
{
   int ret;

   if (!io)
   {
      return 1;
   }

   *io = calloc(1, sizeof(struct io_connection));

   ret = io_uring_queue_init_params(io_ctx->entries, &(*io)->ring, &io_ctx->params);
   if (ret)
   {
      fprintf(stderr, "%s\n", strerror(-ret));
      return 1;
   }

   /* TODO: manage concurrency */
   for (int i = 0; i < CONNECTIONS; i++)
   {
      if (!io_ctx->connections[i])
      {
         io_ctx->connections[i] = *io;
         (*io)->id = i;
         break;
      }
   }

   io_setup_buffer_rings(io);

   return 0;
}

int
io_context_setup()
{
//   int ret;
   struct io_uring_buf_reg reg;

   io_ctx = mmap(NULL, (1 << 14),
               PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_SHARED, -1, 0);
   if (io_ctx == MAP_FAILED)
   {
      perror("mmap");
      return -1;
   }

   memset(io_ctx, 0, sizeof(struct io_context));

   /* TODO: Implement opts support -> each opts below should be able to be set during setup */
   /* TODO: Implement huge pages setup */

   /* setup params */

   io_ctx->entries = (1 << 10);
   io_ctx->params.cq_entries = (1 << 10);
   io_ctx->params.flags = 0;
   io_ctx->params.flags |= IORING_SETUP_SINGLE_ISSUER; /* TODO: makes sense for pgagroal? */
   io_ctx->params.flags |= IORING_SETUP_CLAMP;
   io_ctx->params.flags |= IORING_SETUP_CQSIZE;

   if (defer_tw && sqpoll)
   {
        fprintf(stderr, "Cannot use DEFER_TW and SQPOLL at the same time\n");
        exit(1);
   }

   if (defer_tw)
   {
      (io_ctx)->params.flags |= IORING_SETUP_DEFER_TASKRUN; /* overwritten by SQPOLL */
   }
    
   if (sqpoll)
   {
      (io_ctx)->params.flags |= IORING_SETUP_SQPOLL;
      (io_ctx)->params.sq_thread_idle = 1000;
   }

   if (!sqpoll && !defer_tw)
   {
      (io_ctx)->params.flags |= IORING_SETUP_COOP_TASKRUN;
   }

   /* setup shared buffer */
   /* buffer setup */

   if (!(io_ctx)->br_count)
   {
      (io_ctx)->br_count = (1 << 10);
   }

   if (!(io_ctx)->buffer_ring_size)
   {
      (io_ctx)->buffer_ring_size = (1 << 10);
   }

   if (!io_ctx->br_size)
   {
      io_ctx->br_size = BUFFER_SIZE;
   }

   io_ctx->br_mask = (io_ctx->br_count - 1);
   /* TODO: implement fixed files support */

   return 0;
}

struct io_uring_sqe *io_get_sqe(struct io_uring *ring)
{
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
io_prepare_accept(struct io_connection *io)
{
   struct io_uring_sqe *sqe = io_get_sqe(&io->ring);

   io_encode_data(sqe, ACCEPT, io->id, io->in_br.bgid, io->in_fd);

   io_uring_prep_multishot_accept(sqe, io->in_fd, NULL, NULL, 0);

   return 0;
}

int
io_prepare_receive(struct io_connection *io)
{
   struct io_uring_sqe *sqe = io_get_sqe(&io->ring);

   io_encode_data(sqe, RECEIVE, io->id, io->bid, io->out_fd);

   sqe->buf_index = io->in_br.bgid;
   sqe->flags |= IOSQE_BUFFER_SELECT;
   io_uring_prep_recv_multishot(sqe, io->out_fd, NULL, 0, 0);

   return 0;
}

int
io_prepare_send(struct io_connection *io)
{
   struct io_uring_sqe *sqe = io_get_sqe(&io->ring);

   io_encode_data(sqe, SEND, io->id, io->buffer_id, io->in_fd);

   io_uring_prep_send(sqe, io->in_fd, &io->out_br, io_ctx->br_size, 0);

   return 0;
}

int
io_start()
{
   /* TODO[1]: setup signals to follow up */
   /* TODO[2]: implement fixed_files opt */
   io_uring_queue_init_params(io_ctx->entries, &(io_ctx->main_io->ring), &io_ctx->params);
   io_prepare_accept(io_ctx->main_io);
   io_loop(io_ctx->main_io);

   return 0;
}

int
io_loop(struct io_connection *io) {
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

      i = 0;
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

int
io_recv_ring_setup(struct io_connection *io)
{
   struct io_connection_buf_ring *cbr = &io->in_br;
   int ret, i;
   size_t len;
   void *ptr;

   len = io_ctx->br_size * io_ctx->br_count;
   if (posix_memalign(&cbr->buf, sysconf(_SC_PAGESIZE), len))
   {
      perror("posix memalign");
      return 1;
   }

   cbr->br = io_uring_setup_buf_ring(&io->ring, io_ctx->br_count, cbr->bgid, 0, &ret);
   if (!cbr->br)
   {
      fprintf(stderr, "Buffer ring register failed %d\n", ret);
      return 1;
   }

   ptr = cbr->buf;
   for (i = 0; i < io_ctx->br_count; i++) {
      io_uring_buf_ring_add(cbr->br, ptr, io_ctx->br_count, i, (io_ctx->br_count - 1), i);
      ptr += io_ctx->br_size;
   }
   io_uring_buf_ring_advance(cbr->br, io_ctx->br_count);

   return 0;
}

int
io_setup_send_ring(struct io_connection *io)
{
   struct io_connection_buf_ring *cbr = &io->out_br;
   int ret;

   cbr->br = io_uring_setup_buf_ring(&io->ring, io_ctx->br_count, cbr->bgid, 0, &ret);
   if (!cbr->br) {
      fprintf(stderr, "Buffer ring register failed %d\n", ret);
      return 1;
   }

   return 0;
}

/**
 * TODO: Assess the best size of the buffer rings
 * based on empty buffer rings and consumption speed.
 */
int
io_setup_buffer_ring(struct io_connection_buf_ring *cbr);
int
io_setup_buffer_rings(struct io_connection *io)
{
   int ret;
   ret = io_setup_buffer_ring(&io->in_br);
   ret &= io_setup_buffer_ring(&io->out_br);
   return ret;
}

int
io_setup_buffer_ring(struct io_connection_buf_ring *cbr)
{
   int ret;
   void *br_ptr;

   cbr->bgid = io_ctx->current_bgid++;

   if (posix_memalign(&cbr->buf, sysconf(_SC_PAGESIZE),
                      io_ctx->br_size * io_ctx->br_count))
   {
      perror("io_setup_buffer_ring: posix_memalign");
      return 1;
   }

   cbr->br = io_uring_setup_buf_ring(&io->ring, io_ctx->br_count, cbr->bgid, 0, &ret);
   if (!cbr->br)
   {
      fprintf(stderr, "io_setup_buffer_ring: Buffer ring register failed %d\n", ret);
      return 1;
   }

   br_ptr = (void *) cbr->br;
   for (int bid = 0; bid < io_ctx->br_count; bid++) {
      /* Assign br_ptr with the addr/len/buffer_id supplied.
       * I will be able to retrieve this by bid after. */
      io_uring_buf_ring_add(br_ptr,
                            cbr->buf,
                            io_ctx->br_size,
                            bid,
                            io_ctx->br_mask,
                            bid);
      br_ptr += io_ctx->br_size;
   }
   io_uring_buf_ring_advance(cbr->br, io_ctx->br_count);

   return 0;
}
