/* io.h
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
#include <pthread.h>
#include <liburing.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <err.h>
#include <sys/mman.h>

#define ALIGNMENT sysconf(_SC_PAGESIZE)
#define BUFFER_SIZE (1 << 12) /* 4KiB */
#define BUFFER_POOL_SIZE 4

#define CONNECTIONS (1 << 16)
#define HANDLERS 32
#define FDS 32
#define LENGTH (1 << 20) /* 1 MiB */

struct io_configuration_options {
   bool napi;
   bool sqpoll;
   int sq_thread_idle; /* set to 1000 */
   bool use_huge;
   bool defer_tw;
   bool snd_ring;
   bool snd_bundle;
   bool fixed_files;

   int buf_count;
   int buf_size;
};

struct io;

struct io_configuration
{
   int entries;

   /* configuration */
   bool napi;
   bool sqpoll;
   bool use_huge;
   bool defer_tw;
   bool snd_ring;
   bool snd_bundle;
   bool fixed_files;
   bool ipv6;

   /* ring mapped buffers */
   int buf_size;
   int buf_count;
   size_t buffer_ring_size;
   struct io_uring_buf_ring *buffer_rings;
   uint8_t* buffer_base;  /* apparently the buffer starts after the buffer_rings */

   int br_mask;
   struct io_uring_params params;

   int (*handlers[HANDLERS])(struct io_configuration *, struct io *, struct io_uring_cqe *);
};

struct io_buf_ring {
    struct io_uring_buf_ring *br;
    void *buf;
    int bgid;
};

struct io {

   int id;
   int fd[FDS];
   int fd_count;
   struct io_uring ring;
   struct io_uring_sqe *sqe;
   struct io_uring_cqe *cqe;

   /* TODO: Do iovecs ? */
//   int iovecs_nr;
//   struct iovec *iovecs;

   /* buffer ring */
   int bid;
   struct io_buf_ring br;

   int (*handlers[HANDLERS])(struct io_configuration *, struct io *, struct io_uring_cqe *);
};

struct user_data {
    union {
        struct {
            uint8_t op;
            uint16_t id;  /* connection id */
            uint16_t bid; /* buffer index */
            uint16_t fd;
            uint8_t __rsv;
        };
        uint64_t as_u64;
    };
};

union io_sockaddr {
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
};

/* Function Definitions */

/* TODO */
typedef void (*io_event_cb)(int fd, int events, void* user_data);
int io_add_event(struct io *io, int fd, int events, io_event_cb callback, void* user_data);
/********/

struct io* io_cqe_to_connection(struct io_uring_cqe *cqe);
int io_cqe_to_bid(struct io_uring_cqe *cqe);
struct io_uring_sqe *io_get_sqe(struct io *io);

int io_context_setup(struct io_configuration_options config);

int io_prepare_accept(struct io *io, int fd);
int io_prepare_receive(struct io *io, int fd);
int io_prepare_send(struct io *io, int fd, char* data);
int io_prepare_connect(struct io *io, int fd, union io_sockaddr addr);

//int io_prepare_socket(struct io_connection *io, char *host);

int io_start(struct io* main_io, int listening_socket);

int io_init(struct io **io);
int io_loop(struct io *io);
int io_store_fd(struct io *io, int fd);

int io_handle_send(struct io *io, struct io_uring_cqe *cqe);
int io_handle_receive(struct io *io, struct io_uring_cqe *cqe);
int io_handle_accept(struct io *io, struct io_uring_cqe *cqe);
int io_handle_connect(struct io *io, struct io_uring_cqe *cqe);
int io_handle_socket(struct io *io, struct io_uring_cqe *cqe);
int io_handle_signal(struct io *io, struct io_uring_cqe *cqe);

void io_encode_data(struct io_uring_sqe *sqe, uint8_t op, uint16_t id, uint16_t buffer_id, uint16_t fd);
struct user_data io_decode_data(struct io_uring_cqe *cqe);

int io_recv_ring_setup(struct io *io);
int io_setup_send_ring(struct io *io);
int io_setup_buffers(struct io *io);
int io_setup_buffer_ring(struct io *io);


