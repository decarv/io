
#include "../include/io.h"
#include "../include/utils.h"

#define DATA_SIZE 1024

struct client_watcher {
    int fd;
    char *data;
    size_t data_len;
    size_t total_sent;
    size_t total_received;
    struct io_uring_sqe *sqe;
};

struct connection {
    int server_fd;
    int client_fd;
    struct io *io;
};

int
send_cb(void *data, int fd, int err)
{
   return 0;
}

int
receive_cb(void *data, int recv_fd, int err, void* buf, size_t buf_len)
{
   struct connection *conn = (struct connection*) data;
   struct io *io = conn->io;
   int send_fd;

   if (recv_fd == conn->client_fd)
   {
      send_fd = conn->server_fd;
   }
   else
   {
      send_fd = conn->client_fd;
   }

   register_event(io, send_fd, SEND, NULL, buf, buf_len);

   return 0;
}

/**
 * fd: the fd returned by accept
 */
int
accept_cb(void *data, int client_fd, int err, void* buf, size_t buf_len)
{
   struct sockaddr_in client_addr;
   socklen_t client_len = sizeof(client_addr);
   struct connection *conn = (struct connection *) data;
   struct io *io = conn->io;

   if (client_fd < 0)
   {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
         exit(1);
      }
      perror("accept failed");
   }

   struct client_watcher *cw = malloc(sizeof(struct client_watcher));
   if (!cw)
   {
      perror("malloc failed");
      close(client_fd);
   }

   cw->data = malloc(DATA_SIZE);
   if (!cw->data)
   {
      perror("malloc failed");
      close(client_fd);
      free(cw);
   }

   memset(cw->data, 'A', DATA_SIZE);
   cw->data_len = DATA_SIZE;
   cw->total_sent = 0;
   cw->total_received = 0;
   cw->fd = client_fd;

   conn->client_fd = client_fd;

   // Prepare to receive data from the client
   register_event(io, client_fd, RECEIVE, (event_cb) receive_cb, NULL, 0);

   printf("Accepted connection, fd=%d\n", client_fd);

   return 0;
}


int
main(void)
{
   int ret;
   struct connection *conn = malloc(sizeof(struct connection));
   struct io *main_io = NULL;
   int events;
   int listening_socket;
   int server_fd;

   ret = io_context_setup((struct io_configuration_options) {0});
   if (ret)
   {
      fprintf(stderr, "io_context_setup\n");
      return 1;
   }

   ret = ev_init(&main_io, (void*) conn);
   if (ret)
   {
      fprintf(stderr, "io_connection_setup\n");
      return 1;
   }

   conn->io = main_io;

   listening_socket = prepare_in_socket("8800");
   server_fd = prepare_out_socket("8801");

   conn->server_fd = server_fd;

   events = ACCEPT;
   register_event(main_io, listening_socket, events, (event_cb) accept_cb, NULL, 0);
   ev_loop(main_io);

   return 0;
}
