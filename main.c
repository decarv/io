#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include "io.h"

int main(int argc, char** argv)
{
   int ret;

   ret = io_context_setup((struct io_configuration_options) {0});
   if (ret)
   {
      fprintf(stderr, "io_context_setup\n");
      return 1;
   }

   struct io *main_io;
   ret = io_init(&main_io);
   if (ret)
   {
      fprintf(stderr, "io_connection_setup\n");
      return 1;
   }

   prepare_in_socket(main_io);
   prepare_out_socket(main_io);

   io_start();

   return 0;
}