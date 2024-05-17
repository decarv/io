/* io.c
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 */

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


struct io_ctx {
   int entries;

   int init_opt;
   struct io_uring_params params;

   /* use_mem used to set init_mem
    *  The io_uring_queue_init_mem(3) variant uses the provided buf with
    *  associated size buf_size as the memory for the ring, using the
    *  IORING_SETUP_NO_MMAP flag to io_uring_setup(2).  The buffer
    *  passed to io_uring_queue_init_mem(3) must already be zeroed.
    *  Typically, the caller should allocate a huge page and pass that
    *  in to io_uring_queue_init_mem(3).  Pages allocated by mmap are
    *  already zeroed.  io_uring_queue_init_mem(3) returns the number of
    *  bytes used from the provided buffer, so that the app can reuse
    *  the buffer with the returned offset to put more rings in the same
    *  huge page.
    */
   struct io_uring_buf buf;  // TODO: confirm this is struct io_uring_buf
   size_t buf_size;
};

struct io {
   struct io_uring ring;
   struct io_uring_sqe *sqe;
   struct io_uring_cqe *cqe;
   struct iovec *iovecs;
   int iovecs_nr;
   char buf[1024];
};

int io_init(struct io *io, const struct io_ctx *ctx) {
   int ret;

   if (ctx->init_opt == 1) {
      errx(1, "Not implemented.\n");
   } else if (ctx->init_opt == 2) {
      ret = io_uring_queue_init_mem(ctx->entries, &(io->ring), &(ctx->params), &(ctx->buf), ctx->buf_size);
      if (ret) {
         errx(1, "io_uring_queue_init_mem\n");
      }
   } else {
      ret = io_uring_queue_init(ctx->entries, &(io->ring), ctx->params.flags);
      if (ret < 0) {
         perror("io_uring_queue_init\n");
         return 1;
      }
   }

   return 0;
}

void io_free(struct io *io)
{
   for (int i = 0; i < io->iovecs_nr; i++) {
      free(io->iovecs);
   }
   free(io);

}

