/* io.h
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 *
 * This code is based on: https://git.kernel.dk/cgit/liburing/tree/examples/proxy.c
 * (C) 2024 Jens Axboe <axboe@kernel.dk>
 */

#ifndef EV_H
#define EV_H

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
#include <stdatomic.h>
#include <sys/epoll.h>

#define ALIGNMENT sysconf(_SC_PAGESIZE)  /* TODO: should be used for huge_pages */
#define BUFFER_SIZE (1 << 14) /* 4KiB */
#define BUFFER_COUNT 8        /* 4KiB * 8 = 32 KiB */

#define EMPTY -1
#define MISC_LENGTH (1 << 15) /* 8KiB */

#define MAX_FDS      (1 << 3)  /* this is limited by the value of 'ind' in user data */
#define MAX_SIGNALS  (1 << 3)  /* this is limited by the value of 'ind' in user data */
#define MAX_PERIODIC (1 << 3)  /* this is limited by the value of 'ind' in user data */
#define MAX_EVENTS   (MAX_FDS + MAX_SIGNALS + MAX_PERIODIC)

enum supported_events {
    ACCEPT    = 0,
    RECEIVE   = 1,
    SEND      = 2,
    CONNECT   = 3,
    SOCKET    = 4,
    READ      = 5,
    WRITE     = 6,
    IO_EVENTS_NR = 7,  /* TODO: This is ugly. Find a better way to do this. */
    SIGNAL    = 8,
    PERIODIC  = 9,
    EVENTS_NR = 10,
};

enum supported_signals {
    _SIGTERM = 0,
    _SIGHUP,
    _SIGINT,
    _SIGTRAP,
    _SIGABRT,
    _SIGALRM,
};

/* Return codes used for passing states around */
enum return_codes {
   OK = 0,
   ERROR = 1,
   CLOSE_FD,
   REPLENISH_BUFFERS,
   REARMED,
};

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

struct io_buf_ring
{
   struct io_uring_buf_ring* br;
   void* buf;
   int bgid;
};

struct user_data
{
    union
    {
        struct
        {
            uint8_t event;
            uint8_t bid;    /* unused: buffer index */
            uint16_t id;     /* unused: connection id */
            uint16_t fd;
            uint16_t ind;     /* index of the table used to retrieve the callback associated with the event */
        };
        uint64_t as_u64;
    };
};

struct io_entry
{
    int fd;
    io_cb cbs[IO_EVENTS_NR]; /* either accept, read or write callback */
};

struct signal_entry
{
    int signum; /* signum is not being used in the current implementation (refer to [1]) */
    signal_cb cb;
};

struct periodic_entry
{
    struct __kernel_timespec ts;
    periodic_cb cb;
};

struct ev_entry
{
   int event;
   event_cb cb;
   void * buf;
   size_t buf_len;
   struct epoll_event epoll_ev;
};

union sockaddr_u
{
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
};

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

struct ev_config
{
#ifdef USE_IO_URING
   int entries;

   /* startup configuration */
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
   uint8_t* buffer_base;

   int br_mask;
   struct io_uring_params params;

#else /* use epoll */
   int flags;

#endif
};

struct ev
{
    atomic_bool running; /* used to kill the loop */

    struct ev_config conf;
    int id;

    sigset_t sigset;

    int signal_count;
    int monitored_signals[MAX_SIGNALS];
    struct signal_entry sig_table[MAX_SIGNALS];

#ifdef USE_IO_URING

   int io_count;
   struct io_entry io_table[MAX_FDS];

   uint64_t expirations;
   int periodic_count;
   struct periodic_entry per_table[MAX_PERIODIC];

   struct io_uring ring;
   struct io_uring_sqe* sqe;
   struct io_uring_cqe* cqe;
   int bid; /* next buffer ring id */
   int next_out_bid;
   struct io_buf_ring in_br;
   struct io_buf_ring out_br;

  /* TODO: Do iovecs ?
    *  int iovecs_nr;
    *  struct iovec *iovecs;
    */

#else /* use epoll */

   int epoll_fd;
   int flags;
   int events_nr;
   struct ev_entry ev_table[MAX_EVENTS];
   int ev_table_imap[MAX_EVENTS];  /* inverse map: fd -> ev_table_i */
   int signalfd;
#endif

    void* data;  /* pointer to user defined data that can be retrieved from inside of functions */
};

int ev_init(struct ev** ev_out, void* data, struct ev_setup_opts opts);
int ev_free(struct ev** ev_out);
int ev_loop(struct ev* ev);
#ifdef USE_IO_URING
int ev_handler(struct ev* ev,struct io_uring_cqe* cqe);
#else
int ev_handler(struct ev* ev, int);
int ev_table_insert(struct ev* ev, int fd, int event, event_cb cb, void* buf, size_t buf_len);
int ev_table_remove(struct ev* ev, int ti);
#endif
int ev_setup(struct ev_config* conf, struct ev_setup_opts opts);

int io_init(struct ev* io, int fd, int event, io_cb callback, void* buf, size_t buf_len, int bid);
int io_stop();
int io_accept_init(struct ev* ev,int fd,io_cb cb);
int io_read_init(struct ev* ev,int fd,io_cb cb);
int io_receive_init(struct ev* ev,int fd,io_cb cb);
int io_connect_init(struct ev* ev,int fd,io_cb cb,union sockaddr_u* addr);
int io_send_init(struct ev* ev,int fd,io_cb cb,void* buf,int buf_len,int bid);
int io_table_insert(struct ev* ev, int fd, io_cb cb, int event);
#ifdef USE_IO_URING
int io_handler(struct ev* ev, struct io_uring_cqe* cqe);
int send_handler(struct ev* ev, struct io_uring_cqe* cqe);
int receive_handler(struct ev* ev, struct io_uring_cqe* cqe, void** buf, int*, bool is_proxy);
int accept_handler(struct ev* ev, struct io_uring_cqe* cqe);
int connect_handler(struct ev* ev, struct io_uring_cqe* cqe);
int socket_handler(struct ev* ev, struct io_uring_cqe* cqe, void** buf, int*);
#else
int io_handler(struct ev* ev);
int send_handler(struct ev* ev, int t_index);
int receive_handler(struct ev* ev, int t_index);
int accept_handler(struct ev* ev, int t_index);
int connect_handler(struct ev* ev, int t_index);
#endif

/** Creates a periodic timeout.
 * Uses io_uring_prep_timeout to create a timeout.
 * @param ev:
 * @param msec:
 * @param cb:
 * @return
 */
int periodic_init(struct ev* ev, int msec, periodic_cb cb);
int periodic_stop();
int periodic_table_insert(struct ev* ev, struct __kernel_timespec ts, periodic_cb cb);
int periodic_handler(struct ev* ev, int t_index);

int signal_init(struct ev* io, int signum, signal_cb cb);
int signal_stop();
int signal_table_insert(struct ev* ev, int signum, signal_cb cb);
/** Handles the triggered signals.
 * [1] *NOTE*: the io_uring implementation currently receives signum as a workaround.
 * Remember that the ideal way to deal with signals here may be through signalfd and
 * registering the signals to a table. It is cleaner and it is consistent with the rest
 * of the event handling.
 */
#ifdef USE_IO_URING
int signal_handler(struct ev* ev, int t_index, int signum);
#else
int signal_handler(struct ev* ev, int ti);
#endif /* USE_IO_URING */


#ifdef USE_IO_URING
/**
 * @param fd: either the file descriptor or signum.
 * @param ind: respective table index where the callback is found.
 */
void encode_user_data(struct io_uring_sqe* sqe,uint8_t event,uint16_t id,uint8_t bid,uint16_t fd,uint16_t ind);
struct user_data decode_user_data(struct io_uring_cqe* cqe);
struct io_uring_sqe* get_sqe(struct ev* ev);
int rearm_receive(struct ev* ev, int fd, int t_index);
int prepare_send(struct ev* ev, int fd, void* buf, size_t data_len, int t_index);
int ev_setup_buffers(struct ev* ev);
int replenish_buffers(struct ev* ev, struct io_buf_ring *br, int bid_start, int bid_end);
#endif

int set_non_blocking(int fd);

#endif /* EV_H */