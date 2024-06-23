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
#include <sys/signalfd.h>

#define ALIGNMENT sysconf(_SC_PAGESIZE)
#define BUFFER_SIZE (1 << 14) /* 4KiB */
#define BUFFER_COUNT 8        /* 4KiB * 8 = 32 KiB */

#define MAX_FDS 8
#define EMPTY_FD -1
#define MISC_LENGTH (1 << 20) /* 1 MiB */
#define MAX_SIGNALS  8
#define MAX_PERIODIC 8
#define MAX_EVENTS   32

/**
 *
 */
enum {
    __SIGTERM = 0,
    __SIGHUP,
    __SIGINT,
    __SIGTRAP,
    __SIGABRT,
    __SIGALRM,
};

enum events_enum {
    ACCEPT    = 0,
    RECEIVE   = 1,
    SEND      = 2,
    CONNECT   = 3,
    SOCKET    = 4,
    IO_EVENTS_NR = 5,
    SIGNAL    = 5,
    PERIODIC  = 6,
    READ      = 7,
    WRITE     = 8,
    EVENTS_NR = 9,
};

//enum io_events_enum {
//    ACCEPT   = __ACCEPT,
//    RECEIVE  = __RECEIVE,
//    SEND     = __SEND,
//    CONNECT  = __CONNECT,
//    SOCKET   = __SOCKET,
//    IO_EVENTS_NR,
//};

struct ev_setup_opts
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

struct ev;

/*
 * Data needs to contain io and then be casted.
 */
typedef int (*io_handler)(struct ev*, struct io_uring_cqe*, void**, int*);

/* Define a function pointer type for I/O callbacks */
typedef int (*io_cb)(void* data, int fd, int err, void* buf, size_t buf_len);
/* Define a function pointer type for signal callbacks */
typedef int (*signal_cb)(void* data, int err);
/* Define a function pointer type for periodic callbacks */
typedef int (*periodic_cb)(void* data, int err);

/* Define a union that can hold any of the above callback types */
typedef union event_cb
{
   io_cb io;
   signal_cb signal;
   periodic_cb periodic;
} event_cb;


struct ev_config
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

   int pipe_fds[2];

   bool epoll;
};

struct io_buf_ring
{
   struct io_uring_buf_ring* br;
   void* buf;
   int bgid;
};

struct io_entry
{
   int fd;
   io_cb cbs[IO_EVENTS_NR]; /* either accept, read or write callback */
};

struct signal_entry
{
   int signum;
   signal_cb cb;
};

struct periodic_entry
{
   struct __kernel_timespec ts;
   periodic_cb cb;
};

struct ev
{
   struct ev_config conf;

   int id;

   int io_count;
   struct io_entry io_table[MAX_FDS];

   sigset_t sigset;
   int signal_count;
   int monitored_signals[MAX_SIGNALS];
   struct signal_entry sig_table[MAX_SIGNALS];

   uint64_t expirations;
   int periodic_count;
   struct periodic_entry per_table[MAX_PERIODIC];

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

    void* data;  /* pointer to user defined data that can be retrieved from inside of functions */
};

struct user_data
{
   union
   {
      struct
      {
         uint8_t event;
         uint16_t id;     /* connection id */
         uint8_t bid;    /* buffer index */
         uint16_t fd;
         uint16_t ind;
      };
      uint64_t as_u64;
   };
};

union sockaddr_u
{
   struct sockaddr_in addr4;
   struct sockaddr_in6 addr6;
};

struct periodic
{
    double interval;
    int fd;
    void (*cb)(void);
};

/* Function Definitions */

int io_init(struct ev* io, int fd, int event, io_cb callback, void* buf, size_t buf_len);
int register_io(struct ev* io, int fd, int event, event_cb callback, void* buf, size_t buf_len);

struct ev* io_cqe_to_connection(struct io_uring_cqe* cqe);
int io_cqe_to_bid(struct io_uring_cqe* cqe);
struct io_uring_sqe*io_get_sqe(struct ev* io);

int ev_setup(struct ev_setup_opts opts);

int prepare_accept(struct ev* io, int fd);
int prepare_receive(struct ev* io, int fd);
int prepare_send(struct ev* io, int fd, void* buf, size_t data_len);
int prepare_connect(struct ev* io,int fd,union sockaddr_u addr);
int prepare_read(struct ev* io, int fd, int op);

int prepare_signal(struct ev* io, int fd);
int prepare_periodic(struct ev* io, int fd);

int prepare_socket(struct ev *ev, char *host);

int io_start(struct ev* main_io,int listening_socket);

int ev_init(struct ev** io, void* data);
int io_cleanup(struct ev* io);
int ev_loop(struct ev* io);
int io_register_fd(struct ev* io,int fd);

int handle_event(struct ev* io,struct io_uring_cqe* cqe);

int send_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int*);
int receive_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int*);
int accept_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int*);
int connect_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int*);
int socket_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int*);
int signal_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int*);
int periodic_handler(struct ev* io, struct io_uring_cqe* cqe, void** buf, int*);

/**
 * @param fd: either the file descriptor or signum.
 * @param ind: respective table index where the callback is found.
 */
void encode_user_data(struct io_uring_sqe* sqe, uint8_t event, uint16_t id, uint16_t bid, uint16_t fd, uint16_t ind);
struct user_data decode_user_data(struct io_uring_cqe* cqe);

int io_recv_ring_setup(struct ev* io);
int io_setup_send_ring(struct ev* io);
int io_setup_buffers(struct ev* io);
int io_setup_buffer_ring(struct ev* io);

int fd_table_lookup(struct ev *io, int fd);
int signal_table_lookup(struct ev *ev, int signum);
int periodic_table_lookup(struct ev *ev, int periodic);

int io_next_entry(struct ev* io);
int signal_init(struct ev* io, int signum, signal_cb cb);
int register_signal(struct ev* io, int signum, signal_cb callback);
int handle_signal(struct ev* io, int signum);
int signal_table_insert(struct ev* ev, int signum, signal_cb cb);

int io_table_insert(struct ev* ev, int fd, io_cb cb, int event);

int periodic_table_insert(struct ev* ev, struct __kernel_timespec ts, periodic_cb cb);
int register_periodic(struct ev* ev, struct periodic *p, void (*cb)(void), double interval);
void periodic_start(struct periodic *p);

/** Creates a periodic timeout.
 * Uses io_uring_prep_timeout to create a timeout.
 */
int periodic_init(struct ev* ev, int msec, periodic_cb cb);

/** Wrapper for timerfd_create and timerfd_settime to create interval timers. The file descriptor returned will
 * have to be registered with an event.
 *
 * @param interval Double value representing the interval.
 * @return File descriptor for timer_fd or -1 upon failure.
 */
int periodic_init2(double interval);

bool
is_periodic(int e);

bool
is_signal(int e);

#endif /* IO_H */