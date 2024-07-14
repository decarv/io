#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>
#include <stdatomic.h>
#include <assert.h>
#include <time.h>
#include <errno.h>
#include <sys/wait.h>

#include "ev.h"

#define nr_clients 1
#define nr_messages 50

#define MAX_LENGTH (1 << 17) /* 128 Kib */

struct connection
{
   int id;
   int server_fd;
   int client_fd;
   struct ev* ev;
};

static const char* server_in_port = "8800";
static const char* proxy_in_port = "9900";
struct connection* server_conn;

const int message_length = 1 << 12;
static uint64_t recv_bytes[nr_clients] = { 0 };
static uint64_t sent_bytes[nr_clients] = { 0 };
static uint64_t errors = 0;

int
prepare_out_socket(const char* port)
{
   int ret;
   int fd = -1;
   struct addrinfo hints;
   struct addrinfo* res, * rp;

   memset(&hints, 0, sizeof(hints));
   hints.ai_family = AF_UNSPEC;
   hints.ai_socktype = SOCK_STREAM;

   if ((ret = getaddrinfo("localhost", port, &hints, &res)) != 0)
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

   return fd;
}

int
prepare_in_socket(const char* port)
{
   int optval;
   int fd = -1;
   int ret = 0;
   struct addrinfo hints;
   struct addrinfo* res;
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

   return fd;
}

int
server_receive_callback(void* data, int client_fd, int err, void* buf, size_t buf_len)
{
   char client;
   if (client_fd < 0)
   {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
         exit(1);
      }
      perror("accept failed");
      errors++;
   }

   client = ((char*)buf)[0];
   recv_bytes[client] += buf_len;
   return 0;
}

int
server_accept_callback(void* data, int client_fd, int err, void* buf, size_t buf_len)
{
   struct connection* conn = (struct connection*)data;

   if (client_fd < 0)
   {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
         exit(1);
      }
      perror("accept failed");
      errors++;
   }

   pgagroal_io_receive_init(conn->ev, client_fd, server_receive_callback);

   return 0;
}

void*
server_thread(void* p)
{
   int ret;

   server_conn = malloc(sizeof(struct connection));
   ret = pgagroal_ev_init(&server_conn->ev, server_conn, (struct ev_setup_opts) {0});
   if (ret)
   {
      perror("pgagroal_ev_init");
      return NULL;
   }

   int in_fd = prepare_in_socket(server_in_port);
   pgagroal_io_accept_init(server_conn->ev, in_fd, server_accept_callback);

   pgagroal_ev_loop(server_conn->ev);
//   ev_free(&ev);

   return 0;
}

void*
client_thread(void* p)
{
   pid_t pid;
   int socket;
   srand(time(NULL));

   for (int client = 0; client < nr_clients; client++)
   {
      int size = 128 + (rand() % MAX_LENGTH);
      sent_bytes[client] = size * nr_messages;

      pid = fork();
      if (pid == -1)
      {
         perror("fork");
         exit(EXIT_FAILURE);
      }
      else if (pid == 0)
      {
         socket = prepare_out_socket(server_in_port);
         if (socket < 0)
         {
            perror("client_thread: prepare_out_socket");
            return NULL;
         }
         for (int msg = 0; msg < nr_messages; msg++)
         {
            char* snd_buf = malloc(sizeof(char) * size);
            snd_buf[0] = (char)client;
            send(socket, snd_buf, size, 0);
            usleep(100);
         }
         exit(0);
      }
   }

   wait(NULL);

   atomic_store(&server_conn->ev->running, false);

   for (int i = 0; i < nr_clients; i++)
   {
      assert(sent_bytes[i] == recv_bytes[i]);
   }

   return 0;
}

int
main(int argc, char* argv[])
{
   pthread_t server, proxy, client;

   memset(sent_bytes, 0, sizeof(sent_bytes));
   memset(recv_bytes, 0, sizeof(sent_bytes));

   pthread_create(&server, NULL, server_thread, NULL);
   sleep(1);
   pthread_create(&client, NULL, client_thread, NULL);
   pthread_join(server, NULL);
   pthread_join(client, NULL);

   return 0;
}
