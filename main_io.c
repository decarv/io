#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include "io.h"

int main(int argc, char** argv)
{
   int ret;
   int sock;
   int fd;
   char *port = "8888";
   char buf[2096] = {0};
   struct addrinfo hints;
   struct addrinfo *res;
   struct sockaddr_storage in_addr;
   socklen_t in_addr_sz = sizeof(in_addr);
   struct file_info *fi;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_PASSIVE;

   if ((ret = getaddrinfo(NULL, port, &hints, &res)) < 0) {
      perror("getaddrinfo\n");
      return 1;
   }

   if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol | SO_REUSEADDR)) < 0) {
      perror("socket\n");
      return 1;
   }

   if ((ret = bind(sock, res->ai_addr, res->ai_addrlen)) < 0) {
      perror("bind\n");
      return 1;
   }

   if ((ret = listen(sock, 16)) < 0) {
      perror("listen\n");
      return 1;
   }

   /******************************************/

   struct io_ctx ctx;
   memset(&ctx, 0, sizeof(ctx));
   ctx.entries = 128;

   struct io io;
   memset(&io, 0, sizeof(struct io));

   ret = io_init(&io, &ctx);
   if (ret < 0) {
      perror("io_uring_queue_init\n");
      goto error;
   }

   io.sqe = io_uring_get_sqe(&io.ring);
   io_uring_prep_accept(io.sqe, sock, (struct sockaddr *) &in_addr, &in_addr_sz, 0);
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
   io_uring_prep_recv(io.sqe, conn_sock, io.buf, 1024, 0);
   io_uring_submit(&io.ring);
   ret = io_uring_wait_cqe(&io.ring, &io.cqe);
   if (ret < 0) {
      perror("io_uring_wait_cqe\n");
      goto error;
   }
   io_uring_cqe_seen(&io.ring, io.cqe);
   printf("%s\n", io.buf);

   return 0;

error:
   io_uring_queue_exit(&io.ring);
   return 1;
}