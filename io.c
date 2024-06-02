#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include "io.h"

int main(int argc, char** argv)
{
   int ret;

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

   prepare_in_socket(io_ctx->main_io);
   prepare_out_socket(io_ctx->main_io);

   io_start();

   return 0;
}