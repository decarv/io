#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include "../io.h"

#define ALIGNMENT sysconf(_SC_PAGESIZE)

int prepare_in_socket(int *sock_p)
{
   int ret = 0;
   char *port = "8889";
   struct addrinfo hints;
   struct addrinfo *res;
   memset(&hints, 0, sizeof(hints));

   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_PASSIVE;

   if ((ret = getaddrinfo(NULL, port, &hints, &res)) < 0) {
      perror("getaddrinfo\n");
      return 1;
   }

   if ((*sock_p = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0) {
      perror("socket\n");
      return 1;
   }

   int optval = 1;
   if (setsockopt(*sock_p, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
      perror("setsockopt");
      exit(EXIT_FAILURE);
   }

   if ((ret = bind(*sock_p, res->ai_addr, res->ai_addrlen)) < 0) {
      perror("bind\n");
      return 1;
   }

   if ((ret = listen(*sock_p, 16)) < 0) {
      perror("listen\n");
      return 1;
   }

   return 0;
}

struct io_uring_buf_ring *setup_buffer_ring(struct io *io)
{
   struct io_uring_buf_reg reg = { };
   struct io_uring_buf_ring *br;

   int i;

   /* allocate mem for sharing buffer ring */
   if (posix_memalign((void **) &br, ALIGNMENT,
                      BUFFER_POOL_SIZE * sizeof(struct io_uring_buf_ring)))
      return NULL;

   reg.ring_addr = (unsigned long) br;
   reg.ring_entries = BUFFER_POOL_SIZE;
   reg.bgid = io->conn;  // buff_bgid
   if (io_uring_register_buf_ring(&io->ring, &reg, 0))
      return NULL;

   /* add initial buffers to the ring */
   io_uring_buf_ring_init(br);
   for (i = 0; i < BUFFER_POOL_SIZE; i++) {
      /* add each buffer, we'll use i buffer ID */
      io_uring_buf_ring_add(br, &br->bufs[i], BUFFER_SIZE, i,
                            io_uring_buf_ring_mask(BUFFER_POOL_SIZE), i);
   }

   /* we've supplied buffers, make them visible to the kernel */
   io_uring_buf_ring_advance(br, BUFFER_POOL_SIZE);
   return br;
}

int main(int argc, char** argv)
{
   int ret;
   int sock;
   struct sockaddr_storage in_addr;
   socklen_t in_addr_sz = sizeof(in_addr);

   struct io io = {0};
   struct io_configuration ctx;
   struct io_uring_buf_reg reg = {0};

   prepare_in_socket(&sock);

   struct io_uring_buf_ring buf_pool[BUFFER_SIZE];

   memset(&ctx, 0, sizeof(ctx));
   ctx.entries = 128;

   ret = io_init(&io, &ctx);

   struct io_uring_buf_ring buf_ring = {};
   io_uring_register_buf_ring(&io.ring, &reg, 0);

   if (ret < 0) {
      perror("io_uring_queue_init\n");
      goto error;
   }

   struct io_uring_buf_ring *br = setup_buffer_ring(&io);

   io.sqe = io_uring_get_sqe(&io.ring);
   io_uring_prep_multishot_accept(io.sqe, sock, (struct sockaddr *) &in_addr, &in_addr_sz, 0);
   io_uring_submit(&io.ring);
   ret = io_uring_wait_cqe(&io.ring, &io.cqe);
   if (ret < 0) {
      perror("io_uring_wait_cqe\n");
      goto error;
   }
   io_uring_cqe_seen(&io.ring, io.cqe);
   int conn_sock = io.cqe->res;
   if (conn_sock < 0) {
      fprintf(stderr, "Accept failed: %s\n", strerror(-conn_sock));
      io_uring_cqe_seen(&io.ring, io.cqe);
      io_uring_queue_exit(&io.ring);
      close(sock);
      return 1;
   }

   io.sqe = io_uring_get_sqe(&io.ring);
   io.sqe->flags = IOSQE_BUFFER_SELECT;
   io.sqe->buf_group = io.conn;
   io_uring_prep_recv_multishot(io.sqe, conn_sock, NULL, 0, 0);
   io_uring_submit(&io.ring);
   struct io_uring_cqe *cqe;
   while (1) {
      ret = io_uring_wait_cqe(&io.ring, &cqe);
      if (ret < 0) {
         perror("io_uring_wait_cqe\n");
         goto error;
      }

      if ((cqe->flags & IORING_CQE_F_BUFFER) != 1) {
         errx(1, "cqe did not pick buffer");
      }
      int buf_id;
      buf_id = cqe->flags >> IORING_CQE_BUFFER_SHIFT;
      struct io_uring_buf_ring buf = buf_pool[buf_id];

      io_uring_cqe_seen(&io.ring, cqe);
      printf("%s\n", io.buf);

      sleep(1);
   }

   return 0;

error:
   io_uring_queue_exit(&io.ring);
   return 1;
}