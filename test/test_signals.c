/*
 * Copyright (C) 2024 The pgagroal community
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this list
 * of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, this
 * list of conditions and the following disclaimer in the documentation and/or other
 * materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors may
 * be used to endorse or promote products derived from this software without specific
 * prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 * TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <ev.h>

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

/* Signal call counters */
static volatile int sigterm_calls = 0;
static volatile int sighup_calls = 0;
static volatile int sigint_calls = 0;
static volatile int sigtrap_calls = 0;
static volatile int sigabrt_calls = 0;
static volatile int sigalrm_calls = 0;
static volatile int sigterm_sent = 0;
static volatile int sighup_sent = 0;
static volatile int sigint_sent = 0;
static volatile int sigtrap_sent = 0;
static volatile int sigabrt_sent = 0;
static volatile int sigalrm_sent = 0;

struct arg
{
   pid_t pid;
   struct ev_loop* loop;
};

/* Signal callbacks */

void
sigterm_callback(struct ev_loop* loop, struct ev_signal* watcher, int err)
{
   printf("SIGTERM\n");
   sigterm_calls++;
}

void
sighup_callback(struct ev_loop* loop, struct ev_signal* watcher, int err)
{
   printf("SIGHUP\n");
   sighup_calls++;
}

void
sigint_callback(struct ev_loop* loop, struct ev_signal* watcher, int err)
{
   printf("SIGINT\n");
   sigint_calls++;
}

void
sigtrap_callback(struct ev_loop* loop, struct ev_signal* watcher, int err)
{
   printf("SIGTRAP\n");
   sigtrap_calls++;
}

void
sigabrt_callback(struct ev_loop* loop, struct ev_signal* watcher, int err)
{
   printf("SIGABRT\n");
   sigabrt_calls++;
}

void
sigalrm_callback(struct ev_loop* loop, struct ev_signal* watcher, int err)
{
   printf("SIGALRM\n");
   sigalrm_calls++;
   pgagroal_ev_loop_break(loop);
}

void*
send_signals(void* p)
{
   pid_t pid = *(pid_t*)p;
   printf("pid=%d\n", pid);

   sigset_t set;
   sigemptyset(&set);
   sigaddset(&set, SIGTERM);
   sigaddset(&set, SIGHUP);
   sigaddset(&set, SIGINT);
   sigaddset(&set, SIGTRAP);
   sigaddset(&set, SIGABRT);
   sigaddset(&set, SIGALRM);
   pthread_sigmask(SIG_BLOCK, &set, NULL);

   static struct ev_loop* loop;

   if (kill(pid, SIGTERM) == -1)
   {
      perror("kill");
   }
   sleep(1);
   printf("kill...\n");
   if (kill(pid, SIGHUP) == -1)
   {
      perror("kill");
   }
   sleep(1);
   if (kill(pid, SIGTRAP) == -1)
   {
      perror("kill");
   }
   sleep(1);
   if (kill(pid, SIGINT) == -1)
   {
      perror("kill");
   }
   sleep(1);
   if (kill(pid, SIGABRT) == -1)
   {
      perror("kill");
   }
   sleep(1);
   sleep(5);
   if (kill(pid, SIGALRM) == -1)
   {
      perror("kill");
   }
   return NULL;
}

int
main(void)
{
   int ret;
   pthread_t pthread;
   struct ev_loop* loop = NULL;

   loop = pgagroal_ev_init((struct ev_context) {0});
   if (!loop)
   {
      printf("pgagroal_ev_init\n");
      exit(1);
   }

   ev_signal s1, s2, s3, s4, s5, s6, s7, s8;

   /* Initialize signal handlers */
   pgagroal_ev_signal_init(&s1, sigterm_callback, SIGTERM);
   pgagroal_ev_signal_init(&s2, sighup_callback, SIGHUP);
   pgagroal_ev_signal_init(&s3, sigint_callback, SIGINT);
   pgagroal_ev_signal_init(&s4, sigtrap_callback, SIGTRAP);
   pgagroal_ev_signal_init(&s5, sigabrt_callback, SIGABRT);
   pgagroal_ev_signal_init(&s6, sigalrm_callback, SIGALRM);

   pgagroal_ev_signal_start(loop, &s1);
   pgagroal_ev_signal_start(loop, &s2);
   pgagroal_ev_signal_start(loop, &s3);
   pgagroal_ev_signal_start(loop, &s4);
   pgagroal_ev_signal_start(loop, &s5);
   pgagroal_ev_signal_start(loop, &s6);

   /* cannot test ev_signal_stop because the behaviour here is to stop following up so
    * what is going to happen is the process is going to be killed normally by the signal
    */
   // pgagroal_ev_signal_stop(loop, &s5);

   struct arg param = {
      .pid = getpid(),
      .loop = loop
   };
   printf("pid=%d\n", param.pid);
   sleep(5);
   pthread_create(&pthread, NULL, send_signals, &param);

   pgagroal_ev_loop(loop);

   /* Assert the number of calls for each signal */
   printf("sigterm_calls=%d\n", sigterm_calls);
   assert(1 == sigterm_calls);
   assert(1 == sighup_calls);
   assert(1 == sigint_calls);
   assert(1 == sigtrap_calls);
   assert(1 == sigabrt_calls);
   assert(1 == sigalrm_calls);

   return 0;
}
