
#include "../io.h"
#include "../utils.h"

#define DATA_SIZE 1024

struct client_watcher {
    int fd;
    char *data;
    size_t data_len;
    size_t total_sent;
    size_t total_received;
    struct io_uring_sqe *sqe;
};


int
receive_cb(struct io *io, int fd, int err, void** buf)
{
   printf("receive_cb: contents of buf: %s\n", (char*)*buf);

   return 0;
}

/**
 * fd: the fd returned by accept
 */
int
accept_cb(struct io *io, int client_fd, int err, void** buf)
{
   struct sockaddr_in client_addr;
   socklen_t client_len = sizeof(client_addr);

   if (client_fd < 0)
   {
      if (errno == EAGAIN || errno == EWOULDBLOCK)
      {
         exit(1);
      }
      perror("accept failed");
   }

   struct client_watcher *cw = malloc(sizeof(struct client_watcher));
   if (!cw) {
      perror("malloc failed");
      close(client_fd);
   }

   cw->data = malloc(DATA_SIZE);
   if (!cw->data) {
      perror("malloc failed");
      close(client_fd);
      free(cw);
   }

   memset(cw->data, 'A', DATA_SIZE);
   cw->data_len = DATA_SIZE;
   cw->total_sent = 0;
   cw->total_received = 0;
   cw->fd = client_fd;

   // Prepare to receive data from the client
   io_register_event(io, client_fd, RECEIVE, receive_cb, NULL);

   printf("Accepted connection, fd=%d\n", client_fd);

   return 0;
}


int
main(void)
{
   int ret;
   struct io *main_io = NULL;
   ret = io_context_setup((struct io_configuration_options) {0});
   if (ret)
   {
      fprintf(stderr, "io_context_setup\n");
      return 1;
   }

   ret = io_init(&main_io);
   if (ret)
   {
      fprintf(stderr, "io_connection_setup\n");
      return 1;
   }

   int events;
   int socket = prepare_in_socket();

   events = ACCEPT;
   io_register_event(main_io, socket, events, accept_cb, NULL);
   io_loop(main_io);

   return 0;
}
