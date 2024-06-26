/**
 * This test checks if, during a 'total_time' seconds run, the
 * callbacks cb{1|2|3} are called the expected number of times
 * 'expected_nr_calls_cb{1|2|3}'.
 */

#include <assert.h>
#include <stdio.h>
#include <unistd.h>
#include <pthread.h>
#include "ev.h"

#define ABS(x, y) (x > y ? x - y : y - x)

static int total_time = 1; /* sec */

static int cb1_period = 500; /* msec */
static int nr_calls_cb1 = 0;

static int cb2_period = 100;
static int nr_calls_cb2 = 0;

static int cb3_period = 50;
static int nr_calls_cb3 = 0;

static int
cb1(void* data, int err)
{
   nr_calls_cb1++;
   return 0;
}

static int
cb2(void* data, int err)
{
   nr_calls_cb2++;
   return 0;
}

static int
cb3(void* data, int err)
{
   nr_calls_cb3++;
   return 0;
}

void *
ttl(void* p)
{
   struct ev* ev = (struct ev *) p;
   sleep((int)(total_time));
   atomic_store(&ev->running, false);
   return NULL;
}

int
main(void)
{
   int ret;
   double a, b, c;
   struct ev *ev = NULL;
   pthread_t thread;

   /* sec to msec */
   int expected_nr_calls_cb1 = 1000 * total_time / cb1_period;
   int expected_nr_calls_cb2 = 1000 * total_time / cb2_period;
   int expected_nr_calls_cb3 = 1000 * total_time / cb3_period;

   ret = ev_init(&ev, NULL, (struct ev_setup_opts) {0});
   if (ret)
   {
      fprintf(stderr, "ev_init\n");
      return 1;
   }
   ret = periodic_init(ev, cb1_period, (periodic_cb) cb1);
   if (ret)
   {
      fprintf(stderr, "periodic_init\n");
      return 1;
   }
   ret = periodic_init(ev, cb2_period, (periodic_cb) cb2);
   if (ret)
   {
      fprintf(stderr, "periodic_init\n");
      return 1;
   }
   ret = periodic_init(ev, cb3_period, (periodic_cb) cb3);
   if (ret)
   {
      fprintf(stderr, "periodic_init\n");
      return 1;
   }
   ret = pthread_create(&thread, NULL, ttl, ev);
   if (ret)
   {
      fprintf(stderr, "Error creating thread\n");
      return 1;
   }

   ev_loop(ev);

   assert(ABS(expected_nr_calls_cb1, nr_calls_cb1) <= 1);
   assert(ABS(expected_nr_calls_cb2, nr_calls_cb2) <= 1);
   assert(ABS(expected_nr_calls_cb3, nr_calls_cb3) <= 1);

   return 0;
}
