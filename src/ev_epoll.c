/* ev_epoll.c
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 */

/* system */
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/timerfd.h>
#include <stdatomic.h>

/* project */
#include "../include/ev.h"

int
ev_setup(struct ev_config* conf, struct ev_setup_opts opts)
{
   conf->flags = 0;
   return 0;
}

int
ev_init(struct ev** ev_out, void* data, struct ev_setup_opts opts)
{
   int ret;
   int fd;
   struct ev* ev = calloc(1, sizeof(struct ev));
   if (!ev)
   {
      fprintf(stderr, "calloc\n");
      return -1;
   }

   ev_setup(&ev->conf, opts);

   ev->epoll_fd = epoll_create1(ev->conf.flags);
   if (ev->epoll_fd == -1)
   {
      free(ev);
      fprintf(stderr, "epoll_create1\n");
      return -1;
   }

   /* clean ev_table */
   for (int i = 0; i < MAX_EVENTS; i++)
   {
      ev->ev_table_imap[i] = EMPTY;
      ev->ev_table[i].epoll_ev.data.fd = EMPTY;
   }

   /* signals use sig_table */
   sigemptyset(&ev->sigset);
   fd = signalfd(-1,&ev->sigset,SFD_NONBLOCK);
   if (fd == -1)
   {
      perror("signal_init_epoll: signalfd");
      return ERROR;
   }
   ev->signalfd = fd;
   event_cb nil;
   ev_table_insert(ev, fd, SIGNAL, nil, NULL, 0);


   ev->data = data;

   *ev_out = ev;

   return 0;
}

int
io_accept_init(struct ev* ev, int fd, io_cb cb)
{
   return io_init(ev, fd, ACCEPT, cb, NULL, 0, 0);
}

int
io_receive_init(struct ev* ev, int fd, io_cb cb)
{
   return io_init(ev, fd, RECEIVE, cb, NULL, 0, 0);
}

int
io_send_init(struct ev* ev, int fd, io_cb cb, void* buf, int buf_len, int _rsv)
{
   return io_init(ev, fd, SEND, cb, buf, buf_len, 0);
}

int
io_init(struct ev* ev, int fd, int event, io_cb cb, void* buf, size_t buf_len, int _rsv)
{
   int ret;
   int i;

   ret = set_non_blocking(fd);
   if (ret)
   {
      fprintf(stderr, "set_non_blocking\n");
      return -1;
   }

   ret = ev_table_insert(ev, fd, event, (event_cb)cb, buf, buf_len);
   if (ret)
   {
      fprintf(stdout, "io_init: ev_table_insert\n");
      return ERROR;
   }

   return 0;
}

int
ev_loop(struct ev* ev)
{
   int ret;
   struct epoll_event events[MAX_EVENTS];
   ev->running = true;
   while (atomic_load(&ev->running))
   {
      int nfds = epoll_wait(ev->epoll_fd, events, MAX_EVENTS, 100);
      if (nfds == -1)
      {
         perror("epoll_wait");
         return ERROR;
      }
      for (int i = 0; i < nfds; i++)
      {
         ret = ev_handler(ev, events[i].data.fd);
         if (ret)
         {
            fprintf(stderr, "ev_handler\n");
            return ERROR;
         }
      }
   }
   return OK;
}

int
ev_handler(struct ev* ev, int fd)
{
   int ret;
   int ti;
   int event;

   if (fd == ev->signalfd)
   {
      ret = signal_handler(ev, fd);
   }
   else
   {
      /* table lookup for fd */
      ti = ev->ev_table_imap[fd];
      event = ev->ev_table[ti].event;

      switch (event)
      {
         case ACCEPT:
            ret = accept_handler(ev, ti);
            break;
         case SEND:
            ret = send_handler(ev, ti);
            break;
         case RECEIVE:
            ret = receive_handler(ev, ti);
            break;
         case PERIODIC:
            ret = periodic_handler(ev,ti);
            break;
         default:
            return 1;
      }
   }

   /* deal with ret */
   if (ret == CLOSE_FD)
   {
      ev_table_remove(ev,ti);
   }

   return 0;
}

int
accept_handler(struct ev* ev,int ti)
{
   int listen_fd = ev->ev_table[ti].epoll_ev.data.fd;
   while (1)
   {
      struct sockaddr_in client_addr;
      socklen_t client_len = sizeof(client_addr);
      int client_fd = accept(listen_fd,(struct sockaddr*)&client_addr,&client_len);
      if (client_fd == -1)
      {
         if (errno == EAGAIN || errno == EWOULDBLOCK)
         {
            break;
         }
         else
         {
            fprintf(stderr,"accept\n");
            break;
         }
      }

      if (ev->ev_table[ti].cb.io)
      {
         ev->ev_table[ti].cb.io(ev->data,client_fd,0,0,0);
      }
   }
   return 0;
}

int
receive_handler(struct ev* ev,int ti)
{
   int ret = OK;
   int nrecv = 0;
   int total_recv = 0;
   int capacity = MISC_LENGTH;
   int fd = ev->ev_table[ti].epoll_ev.data.fd;
   void * buf = malloc(sizeof(char) * capacity);
   if (!buf)
   {
      perror("Failed to allocate memory");
      return ALLOC_ERROR;
   }

   while (1)
   {
      nrecv = recv(fd,buf,capacity,0);
      if (nrecv == -1)
      {
         if (errno != EAGAIN && errno != EWOULDBLOCK)
         {
            perror("receive_handler: recv");
         }
         break;
      }
      else if (nrecv == 0) /* connection closed */
      {
         ret = CLOSE_FD;
         goto clean;
      }
      total_recv += nrecv;
      if (total_recv == capacity && capacity < MAX_BUF_LEN)
      {
         int new_capacity = capacity * 2;
         if (new_capacity > MAX_BUF_LEN)
         {
            new_capacity = MAX_BUF_LEN;
         }
         char *new_buf = realloc(buf, new_capacity);
         if (!new_buf)
         {
            perror("Failed to reallocate memory");
            ret = ALLOC_ERROR;
            goto clean;
         }
         buf = new_buf;
         capacity = new_capacity;
      }

      if (capacity == MAX_BUF_LEN && total_recv == capacity)
      {
         break;
      }
   }

   if (ev->ev_table[ti].cb.io)
   {
      ret = ev->ev_table[ti].cb.io(ev->data,fd,0,(void*) buf,total_recv);
   }

clean:
   free(buf);
   return ret;
}

int
send_handler(struct ev* ev,int ti)
{
   int fd = ev->ev_table[ti].epoll_ev.data.fd;
   ssize_t nsent;
   size_t total_sent = 0;
   void* buf = ev->ev_table[ti].buf;
   size_t buf_len = ev->ev_table[ti].buf_len;

   while (total_sent < buf_len)
   {
      nsent = send(fd,buf + total_sent,buf_len - total_sent,0);
      if (nsent == -1)
      {
         if (errno != EAGAIN && errno != EWOULDBLOCK)
         {
            perror("send");
            break;
         }
         else if (errno == EPIPE)
         {
            return CLOSE_FD;
         }
      }
      else
      {
         total_sent += nsent;
      }
   }
   if (total_sent < buf_len)
   {
      io_send_init(ev,fd,ev->ev_table[ti].cb.io,buf + total_sent,buf_len - total_sent,0);
   }

   return 0;
}

int
signal_init(struct ev* ev,int signum,signal_cb cb)
{
   int ret;
   int fd;

   sigaddset(&ev->sigset,signum);

   ret = sigprocmask(SIG_BLOCK,&ev->sigset,NULL);
   if (ret == -1)
   {
      perror("signal_init_epoll: sigprocmask");
      return -1;
   }

   fd = signalfd(ev->signalfd,&ev->sigset,SFD_NONBLOCK);
   if (fd == -1)
   {
      perror("signal_init_epoll: signalfd");
      return ERROR;
   }

   ret = signal_table_insert(ev,signum,cb);
   if (ret)
   {
      fprintf(stdout,"signal_init_epoll: ev_table_insert\n");
      close(fd);
      return ERROR;
   }

   return OK;
}

int
signal_table_insert(struct ev* ev,int signum,signal_cb cb)
{
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
}

int
signal_handler(struct ev* ev,int sfd) {
   int ret;
   struct signalfd_siginfo info;

   ret = read(sfd, &info, sizeof(info));
   if (ret != sizeof(info))
   {
      perror("signal_handler: read");
      return ERROR;
   }

   int signum = info.ssi_signo;
   if (signum >= 0)
   {
      switch (signum) {
         case SIGTERM:
            ev->sig_table[_SIGTERM].cb(ev->data, 0);
            break;
         case SIGHUP:
            ev->sig_table[_SIGHUP].cb(ev->data, 0);
            break;
         case SIGINT:
            ev->sig_table[_SIGINT].cb(ev->data, 0);
            break;
         case SIGTRAP:
            ev->sig_table[_SIGTRAP].cb(ev->data, 0);
            break;
         case SIGABRT:
            ev->sig_table[_SIGABRT].cb(ev->data, 0);
            break;
         case SIGALRM:
            ev->sig_table[_SIGALRM].cb(ev->data, 0);
            break;
         default:
            fprintf(stderr, "signal not supported\n");
            return 1;
      }
   }
   return 0;
}

int
ev_table_insert(struct ev* ev,int fd,int event,event_cb cb,void* buf,size_t buf_len)
{
   int ret;
   int i,ti;
   struct ev_entry* table = ev->ev_table;

   if (ev->ev_table_imap[fd] == EMPTY)
   {
      /* get next empty ti */
      for (i = 0; i < MAX_EVENTS; i++)
      {
         if (ev->ev_table[i].epoll_ev.data.fd == EMPTY)
         {
            ti = i;
            break;
         }
      }
      if (i >= MAX_EVENTS)
      {
         fprintf(stderr,"ev_table_insert: table is full\n");
         return ERROR;
      }

      ev->ev_table_imap[fd] = ti;
   }
   else  /* the file descriptor is already inserted, keep the position in the table */
   {
      ti = ev->ev_table_imap[fd];
   }

   table[ti].epoll_ev.data.fd = fd;
   table[ti].event = event;
   table[ti].cb = cb;
   table[ti].buf = buf;
   table[ti].buf_len = buf_len;

   switch (event)
   {
      case READ:
      case ACCEPT:
      case RECEIVE:
      case SIGNAL:
      case PERIODIC:
         ev->ev_table[ti].epoll_ev.events = EPOLLIN | EPOLLET;
         break;
      case WRITE:
      case SEND:
         ev->ev_table[ti].epoll_ev.events = EPOLLOUT | EPOLLET;
         break;
      default:
         return 1;
   }

   ret = epoll_ctl(ev->epoll_fd,EPOLL_CTL_ADD,fd,&table[ti].epoll_ev);
   if (ret == -1)
   {
      perror("epoll_ctl: listen_fd");
      return 1;
   }

   return OK;
}

int
ev_table_remove(struct ev* ev,int ti)
{
   int ret;
   int fd = ev->ev_table[ti].epoll_ev.data.fd;

   /* removal */
   ev->ev_table_imap[fd] = EMPTY;
   ev->ev_table[ti].epoll_ev.data.fd = EMPTY;

   ret = epoll_ctl(ev->epoll_fd,EPOLL_CTL_DEL,fd,NULL);
   if (ret == -1)
   {
      perror("ev_table_remove: epoll_ctl");
   }

   ret = close(fd);
   if (ret == -1) /* returned errno: EBADF || EIO || EINTR || ENOSPC */
   {
      return 1;
   }


   return 0;
}

int
periodic_init(struct ev* ev,int msec,periodic_cb cb)
{
   int ret;
   int fd;
   int sec,nsec;
   struct timespec now;
   struct itimerspec new_value;

   /* TODO:
    *  what kind of clock to use?
    */
   ret = clock_gettime(CLOCK_MONOTONIC,&now);
   if (ret == -1)
   {
      perror("clock_gettime");
      return ERROR;
   }

   sec = msec / 1000;
   nsec = (msec % 1000) * 1000000;

   new_value.it_value.tv_sec = sec;
   new_value.it_value.tv_nsec = nsec;

//   if (new_value.it_value.tv_nsec >= 1000000000)
//   {
//      new_value.it_value.tv_sec += 1;
//      new_value.it_value.tv_nsec -= 1000000000;
//   }

   new_value.it_interval.tv_sec = sec;
   new_value.it_interval.tv_nsec = nsec;

   fd = timerfd_create(CLOCK_MONOTONIC,TFD_NONBLOCK);  /* no need to set it to non-blocking due to TFD_NONBLOCK */

   ret = timerfd_settime(fd,0,&new_value,NULL);
   if (ret == -1)
   {
      perror("timerfd_settime");
      return ERROR;
   }

   ret = ev_table_insert(ev,fd,PERIODIC,(event_cb)cb,NULL,0);
   if (ret)
   {
      fprintf(stderr,"periodic_init: ev_table_insert\n");
      close(fd); /* TODO: any other error cleanups? */
      return ERROR;
   }

   return OK;
}

int
periodic_handler(struct ev* ev,int ti)
{
   struct ev_entry* table = ev->ev_table;
   uint64_t exp;
   int fd = table[ti].epoll_ev.data.fd;
   int nread = read(fd,&exp,sizeof(uint64_t));
   if (nread != sizeof(uint64_t))
   {
      perror("periodic_handler: read");
      return ERROR;
   }
   table[ti].cb.signal(ev->data,0);
   return OK;
}

int
ev_free(struct ev** ev_out)
{
   if (ev_out == NULL || *ev_out == NULL)
   {
      return OK;
   }

   int ti;
   struct ev* ev = *ev_out;

   /* remove valid descriptors from ev_table */
   for (int fd = 0; fd < MAX_FDS; fd++)
   {
      ti = ev->ev_table_imap[fd];
      if (ti != EMPTY)
      {
         ev_table_remove(ev,ti);
      }
   }

   close(ev->epoll_fd);

   free(ev);

   *ev_out = NULL;

   return OK;
}

int
set_non_blocking(int fd)
{
   int flags = fcntl(fd,F_GETFL,0);
   if (flags == -1)
   {
      return -1;
   }
   return fcntl(fd,F_SETFL,flags | O_NONBLOCK);
}
