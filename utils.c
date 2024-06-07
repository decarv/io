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

char* client_port = "8800";
char* server_port = "8801";

int
prepare_out_socket()
{
   int ret = 0;
   int fd = -1;
   struct addrinfo hints;
   struct addrinfo *res;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;

   if ((ret = getaddrinfo("localhost", server_port, &hints, &res)) < 0)
   {
      perror("getaddrinfo\n");
      return 1;
   }

   if ((fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol)) < 0)
   {
      perror("socket\n");
      return 1;
   }

   if (connect(fd, res->ai_addr, res->ai_addrlen) < 0)
   {
      fprintf(stdout, "Error connecting to server");
      return 1;
   }

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

   ret = getaddrinfo(NULL, client_port, &hints, &res);
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

   return fd;
}
