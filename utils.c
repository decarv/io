/* utils.c
 * Copyright (C) 2024 Henrique de Carvalho <decarv.henrique@gmail.com>
 */

/* system */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netdb.h>

/* io lib */
#include "io.h"

const char* port = "8800";
const char* server_port = "8801";

int prepare_out_socket()
{
   int ret;
   int fd = -1;
   struct addrinfo hints;
   struct addrinfo *res, *rp;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;

   if ((ret = getaddrinfo("localhost", server_port, &hints, &res)) != 0)
   {
      fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret));
      return -1;
   }

   for (rp = res; rp != NULL; rp = rp->ai_next)
   {
      fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd == -1)
      {
         continue;
      }

      if (connect(fd, rp->ai_addr, rp->ai_addrlen) != -1)
      {
         break;
      }

      close(fd);
   }

   if (rp == NULL)
   {
      fprintf(stderr, "Could not connect\n");
      return -1;
   }

   freeaddrinfo(res);

   printf("created socket -> %d\n", fd);

   return fd;
}

int
prepare_in_socket()
{
   int optval;
   int fd = -1;
   int ret = 0;
   struct addrinfo hints;
   struct addrinfo *res;
   memset(&hints, 0, sizeof(hints));

   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;
   hints.ai_flags = AI_PASSIVE;

   ret = getaddrinfo(NULL, port, &hints, &res);
   if (ret < 0)
   {
      perror("getaddrinfo\n");
      return 1;
   }

   if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
   {
      perror("socket\n");
      return 1;
   }

   optval = 1;
   ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
   if (ret < 0)
   {
      perror("setsockopt");
      exit(EXIT_FAILURE);
   }

   ret = bind(fd, res->ai_addr, res->ai_addrlen);
   if (ret < 0)
   {
      perror("bind\n");
      return 1;
   }

   ret = listen(fd, 16);
   if (ret < 0)
   {
      perror("listen\n");
      return 1;
   }

   printf("Server listening on port %s...\n", port);

   return fd;
}
