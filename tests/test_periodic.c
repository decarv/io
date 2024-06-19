//
// Created by decarv on 6/17/24.
//

#include <stdio.h>
#include <unistd.h>
#include "io.h"

static int
callback(void* data, int err)
{
   static double time = 0.0;

   time += 1.0;
   printf("%lfs elapsed\n", time);
   return 0;
}

int
main(void)
{
   int ret;
   double a, b, c;
   struct io *io = NULL;
   struct periodic p;
   ret = io_context_setup((struct io_configuration_options) {0});
   if (ret)
   {
      return 1;
   }

   ret = io_init(&io, NULL);
   if (ret)
   {
      return 1;
   }
   int fd = periodic_init(1.0);
   if (fd < 0)
   {
      return 1;
   }
   ret = io_register_event(io, fd, PERIODIC, (event_cb) callback, NULL, 0);
   if (ret)
   {
      fprintf(stderr, "error\n");
      return 1;
   }
   ev_loop(io);
   return ret;
}
