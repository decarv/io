#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
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

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_PASSIVE;

   if ((ret = getaddrinfo(NULL, port, &hints, &res)) < 0) {
      perror("getaddrinfo\n");
      exit(1);
   }

   if ((sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol | SO_REUSEADDR)) < 0) {
      perror("socket\n");
      exit(1);
   }

   if ((ret = bind(sock, res->ai_addr, res->ai_addrlen)) < 0) {
      perror("bind\n");
      exit(1);
   }

   if ((ret = listen(sock, 16)) < 0) {
      perror("listen\n");
      exit(1);
   }

   while (1) {
      fd = accept(sock, (struct sockaddr *) &in_addr, &in_addr_sz);
      while (recv(fd, &(buf[0]), 36, 0) > 0) {
         printf("Data: %s\n", buf);
      }
   }

   return 0;
}