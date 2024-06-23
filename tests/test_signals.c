
#include <signal.h>
#include <time.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "ev_io_uring.h"

int
callback(void* data, int signum)
{
   static int next = 0;
   printf("%d\n", next++);
   return 0;
}


int
main(void)
{
   int ret;
   double a, b, c;
   struct io *io = NULL;
   struct periodic p;

   ret = ev_setup((struct io_configuration_options) {0});
   if (ret)
   {
      return 1;
   }

   ret = ev_init(&io, NULL);
   if (ret)
   {
      return 1;
   }

   int fd = signal_init(io, SIGINT, callback);
   if (fd < 0)
   {
      return 1;
   }

   pid_t pid = fork();
   if (!pid) /* if child */
   {
      pid_t i = getpid();
      printf("%d\n", i);
      struct signalfd_siginfo fdsi;

      ev_loop(io);

   }
   else
   {
      do {
         sleep(2);
         if (kill(pid, SIGINT) == -1)
         {
            perror("kill");
            return 1;
         }
         printf("Sent SIGINT to %d\n", pid);
      } while (1);
   }
   return ret;
}
