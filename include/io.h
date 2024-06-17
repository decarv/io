/* io.h
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 *
 * This code is based on: https://git.kernel.dk/cgit/liburing/tree/examples/proxy.c
 * (C) 2024 Jens Axboe <axboe@kernel.dk>
 */

#ifndef IO_H
#define IO_H

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
#define BUFFER_SIZE (1 << 14) /* 4KiB */
#define BUFFER_COUNT 8        /* 4KiB * 8 = 32 KiB */
#define MAX_SIGNALS 32

#define CONNECTIONS (1 << 16)
#define EVENTS_NR 8
#define FDS 8
#define LENGTH (1 << 20) /* 1 MiB */

struct io_configuration_options
{
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

/*
 * Data needs to contain io and then be casted.
 */
typedef int (*io_handler)(struct io*, struct io_uring_cqe*, void**, int*);
typedef int (*io_event_cb)(void* data, int fd, int err, void* buf, size_t buf_len);
typedef int (*_signal_event_cb)(int signum);

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
   struct io_uring_buf_ring* buffer_rings;
   uint8_t* buffer_base;  /* apparently the buffer starts after the buffer_rings */

   int br_mask;
   struct io_uring_params params;
};

struct io_buf_ring
{
   struct io_uring_buf_ring* br;
   void* buf;
   int bgid;
};

struct io_returned_buf
{
   void** buf;
   size_t len;
};

union callback
{
   io_event_cb event_cb;
   _signal_event_cb signal_cb;
};

struct fd_entry
{
   int fd;
   union callback callbacks[EVENTS_NR];
};

struct signal_entry
{
   int signum;
   _signal_event_cb callback;
};

struct io
{

   int id;

   struct fd_entry fd_table[FDS];

   struct io_uring ring;
   struct io_uring_sqe* sqe;
   struct io_uring_cqe* cqe;

   /* TODO: Do iovecs ? */
//   int iovecs_nr;
//   struct iovec *iovecs;

   /* buffer ring */
   int bid;
   struct io_buf_ring in_br;
   struct io_buf_ring out_br;

   void* data;

   sigset_t signal_set;


};

struct user_data
{
   union
   {
      struct
      {
         uint8_t op;
         uint16_t id;     /* connection id */
         uint16_t bid;    /* buffer index */
         uint16_t fd;
         uint8_t rsv;
      };
      uint64_t as_u64;
   };
};

union io_sockaddr
{
   struct sockaddr_in addr4;
   struct sockaddr_in6 addr6;
};

enum {
   __SIGTERM = 0,
   __SIGHUP,
   __SIGINT,
   __SIGTRAP,
   __SIGABRT,
   __SIGALRM,
};

enum {
   __ACCEPT  = 0,
   __RECEIVE = 1,
   __SEND    = 2,
   __CONNECT = 3,
   __SOCKET  = 4,
   __SIGNAL  = 5,
   __SIGTERM = 6,
   __SIGHUP  = 7,
   __SIGINT  = 8,
   __SIGTRAP = 9,
   __SIGABRT = 10,
   __SIGALRM = 11,
};

enum {
   ACCEPT  = 1 << __ACCEPT,
   RECEIVE = 1 << __RECEIVE,
   SEND    = 1 << __SEND,
   CONNECT = 1 << __CONNECT,
   SOCKET  = 1 << __SOCKET,
   SIGNAL  = 1 << __SIGNAL,
   SIGHUP,
   SIGINT,
   SIGTRAP,
   SIGABRT,
   SIGALRM,
   SIGTERM,
};

/* Function Definitions */

/* TODO */
int io_register_event(struct io* io,int fd,int events,io_event_cb callback,void* buf,size_t buf_len);
/********/

struct io* io_cqe_to_connection(struct io_uring_cqe* cqe);
int io_cqe_to_bid(struct io_uring_cqe* cqe);
struct io_uring_sqe*io_get_sqe(struct io* io);

int io_context_setup(struct io_configuration_options config);

int io_prepare_accept(struct io* io,int fd);
int io_prepare_receive(struct io* io,int fd);
int io_prepare_send(struct io* io,int fd,void* buf,size_t data_len);
int io_prepare_connect(struct io* io,int fd,union io_sockaddr addr);

//int io_prepare_socket(struct io_connection *io, char *host);

int io_start(struct io* main_io,int listening_socket);

int io_init(struct io** io,void* data);
int io_cleanup(struct io* io);
int io_loop(struct io* io);
int io_register_fd(struct io* io,int fd);

int io_handle_event(struct io* io,struct io_uring_cqe* cqe);

int io_send_handler(struct io* io,struct io_uring_cqe* cqe,void** buf,int*);
int io_receive_handler(struct io* io,struct io_uring_cqe* cqe,void** buf,int*);
int io_accept_handler(struct io* io,struct io_uring_cqe* cqe,void** buf,int*);
int io_connect_handler(struct io* io,struct io_uring_cqe* cqe,void** buf,int*);
int io_socket_handler(struct io* io,struct io_uring_cqe* cqe,void** buf,int*);
int io_signal_handler(struct io* io,struct io_uring_cqe* cqe,void** buf,int*);

void io_encode_data(struct io_uring_sqe* sqe,uint8_t op,uint16_t id,uint16_t bid,uint16_t fd);
struct user_data io_decode_data(struct io_uring_cqe* cqe);

int io_recv_ring_setup(struct io* io);
int io_setup_send_ring(struct io* io);
int io_setup_buffers(struct io* io);
int io_setup_buffer_ring(struct io* io);

int io_table_lookup(struct io* io,int fd);

int io_next_entry(struct io* io);
int io_signals_init(struct io* io);
int io_register_signal(struct io* io,int signum,_signal_event_cb callback);

#endif /* IO_H */