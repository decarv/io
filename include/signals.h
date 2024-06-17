/*
 * This is supposed to use be a wrapper for pgagroal interface:
 *  1. signal_init
 *  2. signal_start
 *  3. signal_stop
 */

#ifndef IO_SIGNALS_H
#define IO_SIGNALS_H

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

struct signal_watcher {
   sigset_t signal_set;
   sighandler_t
};

int
handle_signal(int);

int
handle_signal(int signum)
{
   switch (signum)
   {

   }
   return 0;
}

int
io_signals_init(sigset_t *sigset_p)
{
   struct sigaction new_action, old_action;

   new_action.sa_handler = handler;
   sigemptyset (&new_action.sa_mask);
   new_action.sa_flags = 0;

   sigaction (SIGINT, NULL, &old_action);
   if (old_action.sa_handler != SIG_IGN)
      sigaction (SIGINT, &new_action, NULL);
   sigaction (SIGHUP, NULL, &old_action);
   if (old_action.sa_handler != SIG_IGN)
      sigaction (SIGHUP, &new_action, NULL);
   sigaction (SIGTERM, NULL, &old_action);
   if (old_action.sa_handler != SIG_IGN)
      sigaction (SIGTERM, &new_action, NULL);
   return 0;
}

#endif //IO_SIGNALS_H
