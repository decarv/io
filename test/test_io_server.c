#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>

#define PORT 8801
#define BUFFER_SIZE (1 << 14)

struct event_counter
{
   int client_fd;
   size_t bytes_received;
};

void
handle_client(int client_fd)
{
   struct event_counter counter;
   counter.client_fd = client_fd;
   counter.bytes_received = 0;

   char buffer[BUFFER_SIZE];
   ssize_t bytes_read;

   while ((bytes_read = read(client_fd, buffer, sizeof(buffer) - 1)) > 0)
   {
      buffer[bytes_read] = '\0';
      printf("Received from client %d: %s\n", client_fd, buffer);

      counter.bytes_received += bytes_read;
      printf("Total bytes received from client %d: %zu\n", client_fd, counter.bytes_received);
   }

   if (bytes_read < 0)
   {
      perror("read");
   }

   close(client_fd);
   printf("Client %d disconnected. Total bytes received: %zu\n", client_fd, counter.bytes_received);
}

int
main()
{
   int server_fd, client_fd;
   struct sockaddr_in server_addr, client_addr;
   socklen_t client_addr_len = sizeof(client_addr);

   if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
   {
      perror("socket");
      exit(EXIT_FAILURE);
   }

   memset(&server_addr, 0, sizeof(server_addr));
   server_addr.sin_family = AF_INET;
   server_addr.sin_addr.s_addr = INADDR_ANY;
   server_addr.sin_port = htons(PORT);

   if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
   {
      perror("bind");
      close(server_fd);
      exit(EXIT_FAILURE);
   }

   if (listen(server_fd, 10) < 0)
   {
      perror("listen");
      close(server_fd);
      exit(EXIT_FAILURE);
   }

   int optval = 1;
   int ret = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
   if (ret < 0)
   {
      perror("setsockopt");
      exit(EXIT_FAILURE);
   }

   printf("Server is listening on port %d\n", PORT);

   while ((client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_addr_len)) >= 0)
   {
      printf("Client %d connected\n", client_fd);
      handle_client(client_fd);
   }

   if (client_fd < 0)
   {
      perror("accept");
      close(server_fd);
      exit(EXIT_FAILURE);
   }

   close(server_fd);
   return 0;
}
