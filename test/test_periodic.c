//
// Created by decarv on 6/17/24.
//

#include <stdio.h>
#include <unistd.h>
#include "ev_io_uring.h"

static int
callback1(void* data, int err)
{
   static double time = 0.0;

   time += 1.0;
   printf("%lf\n", time);
   return 0;
}

static int
callback2(void* data, int err)
{
   printf("foo");
   return 0;
}

static int
callback3(void* data, int err)
{
   printf("bar");
   return 0;
}

int
main(void)
{
   int ret;
   double a, b, c;
   struct ev *ev = NULL;
   ret = ev_setup((struct ev_setup_opts) {0});
   if (ret)
   {
      fprintf(stderr, "ev_setup\n");
      return 1;
   }

   ret = ev_init(&ev, NULL);
   if (ret)
   {
      fprintf(stderr, "ev_init\n");
      return 1;
   }
   ret = periodic_init(ev, 1000, (periodic_cb) callback1);
   if (ret)
   {
      return 1;
   }

   ev_loop(ev);
   return ret;
}
