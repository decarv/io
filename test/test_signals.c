#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>
#include "ev.h"

static int expected = 2;

/* Signal call counters */
static volatile int sigterm_calls = 0;
static volatile int sighup_calls = 0;
static volatile int sigint_calls = 0;
static volatile int sigtrap_calls = 0;
static volatile int sigabrt_calls = 0;
static volatile int sigalrm_calls = 0;
static volatile int sigterm_sent = 0;
static volatile int sighup_sent= 0;
static volatile int sigint_sent= 0;
static volatile int sigtrap_sent = 0;
static volatile int sigabrt_sent = 0;
static volatile int sigalrm_sent = 0;

struct conn {
    struct ev* ev;
};

/* Signal callbacks */
int sigterm_callback(void* data, int signum) {
   sigterm_calls++;
   return 0;
}

int sighup_callback(void* data, int signum) {
   sighup_calls++;
   return 0;
}

int sigint_callback(void* data, int signum) {
   sigint_calls++;
   return 0;
}

int sigtrap_callback(void* data, int signum) {
   sigtrap_calls++;
   return 0;
}

int sigabrt_callback(void* data, int signum) {
   sigabrt_calls++;
   return 0;
}

int sigalrm_callback(void* data, int signum) {
   sigalrm_calls++;
   struct conn* c = (struct conn*) data;
   atomic_store(&c->ev->running, false);
   return 0;
}

struct arg {
    struct ev* ev;
    pid_t pid;
};

void *
send_signals(void *p)
{
   struct arg* param = (struct arg*)p;
   struct ev* ev = param->ev;
   pid_t pid = param->pid;


   sigset_t set;
   sigemptyset(&set);
   sigaddset(&set, SIGTERM);
   sigaddset(&set, SIGHUP);
   sigaddset(&set, SIGINT);
   sigaddset(&set, SIGTRAP);
   sigaddset(&set, SIGABRT);
   sigaddset(&set, SIGALRM);
   pthread_sigmask(SIG_BLOCK, &set, NULL);

   for (int i = 0; i < expected; i++)
   {
      if (kill(pid, SIGTERM) == -1)
      {
         perror("kill");
      }
      usleep(100);
      if (kill(pid, SIGHUP) == -1)
      {
         perror("kill");
      }
      usleep(100);
      if (kill(pid, SIGTRAP) == -1)
      {
         perror("kill");
      }
      usleep(100);
      if (kill(pid, SIGINT) == -1)
      {
         perror("kill");
      }
      usleep(100);
      if (kill(pid, SIGABRT) == -1)
      {
         perror("kill");
      }
      usleep(100);

   }
   if (kill(pid, SIGALRM)== -1)
   {
      perror("kill");
   }
   usleep(100);
   return NULL;
}


int
main(void)
{
   int ret;
   struct conn *c = malloc(sizeof(struct conn));
   pthread_t pthread;

   ret = ev_init(&c->ev, c, (struct ev_setup_opts) {0});
   if (ret)
   {
      fprintf(stderr, "ev_init\n");
      return 1;
   }

   struct ev* ev = c->ev;

   /* Initialize signal handlers */
   ret = signal_init(ev, SIGTERM, sigterm_callback);
   if (ret) {
      return 1;
   }
   ret = signal_init(ev, SIGHUP, sighup_callback);
   if (ret) {
      return 1;
   }
   ret = signal_init(ev, SIGINT, sigint_callback);
   if (ret) {
      return 1;
   }
   ret = signal_init(ev, SIGTRAP, sigtrap_callback);
   if (ret) {
      return 1;
   }
   ret = signal_init(ev, SIGABRT, sigabrt_callback);
   if (ret) {
      return 1;
   }
   ret = signal_init(ev, SIGALRM, sigalrm_callback);
   if (ret) {
      return 1;
   }

   struct arg param = {
           .pid = getpid(),
           .ev = ev
   };
   pthread_create(&pthread, NULL, send_signals, &param);

   ev_loop(ev);

   /* Assert the number of calls for each signal */
   assert(expected == sigterm_calls);
   assert(expected == sighup_calls);
   assert(expected == sigint_calls);
   assert(expected == sigtrap_calls);
   assert(expected == sigabrt_calls);
   assert(sigalrm_calls == 1);

//   ev_free(&ev);

   return 0;
}