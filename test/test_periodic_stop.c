/**
 * Copyright Notice.
 *
 */

/**
 * This test checks if, during a 'total_time' seconds run, the
 * callbacks cb{1|2|3} are called the expected number of times
 * 'expected_nr_calls_cb{1|2|3}'.
 */

/* pgagroal */
#include <ev.h>

/* system */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pthread.h>

static int total_time = 1; /* sec */

static int cb1_period = 500; /* msec */
static int nr_calls_cb1 = 0;

static int cb2_period = 100;
static int nr_calls_cb2 = 0;

static int cb3_period = 50;
static int nr_calls_cb3 = 0;

static void
cb1(struct ev_loop* ev, struct ev_periodic* watcher, int err)
{
   nr_calls_cb1++;
}

static void
cb2(struct ev_loop* ev, struct ev_periodic* watcher, int err)
{
   nr_calls_cb2++;
}

void*
ttl(void* p)
{
   struct ev_loop* loop = (struct ev_loop*)p;
   sleep((int)(total_time));
   pgagroal_ev_loop_break(loop);
   return NULL;
}

int
main(void)
{
   int ret;
   double a, b, c;
   pthread_t thread;
   ev_periodic p1, p2, p3;
   int expected_nr_calls_cb1 = 1000 * total_time / cb1_period;
   int expected_nr_calls_cb2 = 1000 * total_time / cb2_period;
   int expected_nr_calls_cb3 = 1000 * total_time / cb3_period;
   static struct ev_loop* loop;
   static struct ev_context ev_ctx = { 0 };

   loop = pgagroal_ev_init(ev_ctx);
   if (!loop)
   {
      fprintf(stderr, "pgagroal_ev_init,loop_is_null=%d\n", loop == NULL);

      exit(1);
   }
   pgagroal_ev_periodic_init(&p1, cb1, cb1_period);
   pgagroal_ev_periodic_init(&p2, cb2, cb2_period);

   pgagroal_ev_periodic_start(loop, &p1);
   pgagroal_ev_periodic_start(loop, &p2);

   ret = pthread_create(&thread, NULL, ttl, loop);
   if (ret)
   {
      fprintf(stderr, "Error creating thread\n");
      return 1;
   }

   pgagroal_ev_periodic_stop(loop, &p2);

   pgagroal_ev_loop(loop);

   assert(abs(expected_nr_calls_cb1, nr_calls_cb1) <= 1);
   assert(nr_calls_cb2 == 0 && abs(expected_nr_calls_cb2, nr_calls_cb2) >= 1);

   return 0;
}
