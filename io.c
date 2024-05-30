#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include "io.h"

int main(int argc, char** argv)
{
   int ret;
   int *listening_socket_p;

   ret = io_context_setup();
   if (ret)
   {
      fprintf(stderr, "io_context_setup\n");
      return 1;
   }

   ret = io_connection_init(&io_ctx->main_io);
   if (ret)
   {
      fprintf(stderr, "io_connection_setup\n");
      return 1;
   }

   listening_socket_p = &io_ctx->main_io->in_fd;
   prepare_listening_socket(listening_socket_p);

   io_start();

   return 0;
}