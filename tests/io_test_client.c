//
// Created by decarv on 6/7/24.
//
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <string.h>

#include "../io.h"

#define NUM_CLIENTS 1
#define NUM_MESSAGES 50

void send_message(int sock, int client, int message)
{
   char msg[256];
   snprintf(msg, sizeof(msg), "Message %d from client %d\n", message, client);
   if (send(sock, msg, strlen(msg), 0) < 0) {
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
         for (int message = 1; message <= nr_messages; message++)
         {
            printf("From Client %d Sending Message %d\n", client, message);
            socket = prepare_out_socket();
            send_message(socket, client, message);
            close(socket);
            sleep(4);
         }
         exit(EXIT_SUCCESS);
      }
   }

   for (int i = 0; i < NUM_CLIENTS; i++)
   {
      wait(NULL);
   }

   return 0;
}
