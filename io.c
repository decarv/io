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

#define BUFF_SZ   512
#define IOU_ENTRIES 128

static struct io_ctx {
   struct io_uring ring;
   char buff[BUFF_SZ + 1];
} ctx;

int main() {
   pthread_t t;
   int ret;
   struct io_uring_sqe *sqe;

   ret = io_uring_queue_init(IOU_ENTRIES, &ctx.ring, 0);

   struct addrinfo hints, *res;
   memset(&hints, 0, sizeof hints);
   hints.ai_family = AF_UNSPEC; // AF_INET or AF_INET6 to force version
   hints.ai_socktype = SOCK_STREAM;

   ret = getaddrinfo("localhost", "http", &hints, &res);
   if (ret)
   {
      perror("getaddrinfo");
   }
   int sockfd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);


   sqe = io_uring_get_sqe(&ctx.ring);
   if (!sqe) {
      io_uring_submit(&ctx.ring);
      sqe = io_uring_get_sqe(&ctx.ring);
   }
   if (!sqe) {
      perror("sqe\n");
      exit(1);
   }

   return EXIT_SUCCESS;
}
