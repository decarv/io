//
// Created by decarv on 6/17/24.
//
/*
 * Have a server running in another thread.
 * Send information over a network to say that
 */
#include "../include/io.h"
#include <unistd.h>

static void
callback(void)
{
   static double time = 0.0;

   time += 1.0;
   printf("%lfs elapsed\n", time);
}

int
main(void)
{
   int ret;
   double a, b, c;
   struct io *io = NULL;
   struct periodic p;
   io_init(&io, NULL);
   ret = register_periodic(io, &p, callback, 1.0);
   while (1)
   {
      usleep(100);
   }
   return ret;
}
