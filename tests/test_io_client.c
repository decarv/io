//
// Created by decarv on 6/7/24.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <string.h>

#include "../include/ev_io_uring.h"
#include "../include/utils.h"

#define NUM_CLIENTS 1
#define NUM_MESSAGES 50
#define MESSAGE_LENGTH (1<<12)

void send_message(int sock, int client, int message)
{
   char msg[MESSAGE_LENGTH];
   int len = snprintf(msg, sizeof(msg), "Message %d from client %d\n", message, client);
   memset(msg + len, 'A', sizeof(msg) - len - 1);
   msg[sizeof(msg) - 1] = '8';
   if (send(sock, msg, strlen(msg), 0) < 0)
   {
      perror("send");
   }
}

int main(int argc, char* argv[])
{
   int nr_clients = NUM_CLIENTS;
   int nr_messages = NUM_MESSAGES;

   if (argc > 2) {
	nr_clients = atoi(argv[1]);
	nr_messages = atoi(argv[2]);
   }

   printf("Starting tests for %d clients and %d messages\n", nr_clients, nr_messages);

   const char * port = "8800";
   pid_t pid;
   int socket;
   for (int client = 1; client <= nr_clients; client++)
   {
      pid = fork();
      if (pid == -1)
      {
         perror("fork");
         exit(EXIT_FAILURE);
      }
      else if (pid == 0)
      {
         socket = prepare_out_socket(port);
         for (int message = 1; message <= nr_messages; message++)
         {
            send_message(socket, client, message);
            usleep(10);
         }
         exit(EXIT_SUCCESS);
      }
   }

   for (int i = 0; i < NUM_CLIENTS; i++)
   {
      wait(NULL);
   }

   if (pid != 0)
   {
      int total_data = nr_clients * nr_messages * MESSAGE_LENGTH;
      printf("%d\n", total_data);
   }

   return 0;
}
