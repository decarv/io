#include <ev.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>

typedef struct {
    int read_events;
    int write_events;
    int signal_events;
} event_counter;

#define PORT 12345
#define MAX_CONNECTIONS 100
#define DATA_SIZE 1024*1024

typedef struct {
    ev_io io;
    int fd;
    char *data;
    size_t data_len;
    size_t total_sent;
    size_t total_received;
} client_watcher;

event_counter counter;

static void read_cb(EV_P_ ev_io *w, int revents);
static void write_cb(EV_P_ ev_io *w, int revents);
static void accept_cb(EV_P_ ev_io *w, int revents);
static void sigint_cb(EV_P_ ev_signal *w, int revents);

int main() {
   struct ev_loop *loop = EV_DEFAULT;
   int sockfd;
   struct sockaddr_in addr;
   ev_io socket_watcher;
   ev_signal signal_watcher;

   ev_signal_init(&signal_watcher, sigint_cb, SIGINT);
   ev_signal_start(loop, &signal_watcher);

   sockfd = socket(AF_INET, SOCK_STREAM, 0);
   if (sockfd < 0) {
      perror("socket creation failed");
      return -1;
   }

   memset(&addr, 0, sizeof(addr));
   addr.sin_family = AF_INET;
   addr.sin_addr.s_addr = INADDR_ANY;
   addr.sin_port = htons(PORT);

   if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      perror("bind failed");
      return -1;
   }

   if (listen(sockfd, MAX_CONNECTIONS) < 0) {
      perror("listen failed");
      return -1;
   }

   int flags = fcntl(sockfd, F_GETFL, 0);
   fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

   ev_io_init(&socket_watcher, accept_cb, sockfd, EV_READ);
   ev_io_start(loop, &socket_watcher);

   ev_run(loop, 0);

   close(sockfd);
   ev_loop_destroy(loop);

   return 0;
}

static void accept_cb(EV_P_ ev_io *w, int revents) {
   struct sockaddr_in client_addr;
   socklen_t client_len = sizeof(client_addr);
   int client_fd = accept(w->fd, (struct sockaddr *)&client_addr, &client_len);
   if (client_fd < 0) {
      perror("accept failed");
      return;
   }

   client_watcher *cw = malloc(sizeof(client_watcher));
   cw->data = malloc(DATA_SIZE);  // Allocate buffer for the "trash" data
   memset(cw->data, 'A', DATA_SIZE);  // Fill buffer with 'A'
   cw->data_len = DATA_SIZE;
   cw->total_sent = 0;
   cw->total_received = 0;

   ev_io_init(&cw->io, read_cb, client_fd, EV_READ);
   ev_io_start(EV_A_ &cw->io);
   cw->fd = client_fd;
}

static void read_cb(EV_P_ ev_io *w, int revents) {
   client_watcher *cw = (client_watcher*) w;
   char buffer[4096];
   ssize_t nread = read(cw->fd, buffer, sizeof(buffer));
   if (nread > 0) {
      cw->total_received += nread;
      if (cw->total_received >= cw->data_len) {
         ev_io_stop(EV_A_ &cw->io);
         ev_io_init(&cw->io, write_cb, cw->fd, EV_WRITE);
         ev_io_start(EV_A_ &cw->io);
      }
   } else {
      ev_io_stop(EV_A_ &cw->io);
      free(cw->data);
      free(cw);
      close(cw->fd);
   }
}

static void write_cb(EV_P_ ev_io *w, int revents) {
   client_watcher *cw = (client_watcher*) w;
   ssize_t nsent = write(cw->fd, cw->data + cw->total_sent, cw->data_len - cw->total_sent);
   if (nsent > 0) {
      cw->total_sent += nsent;
      if (cw->total_sent >= cw->data_len) {
         ev_io_stop(EV_A_ &cw->io);
         free(cw->data);
         free(cw);
         close(cw->fd);
      }
   } else {
      ev_io_stop(EV_A_ &cw->io);
      free(cw->data);
      free(cw);
      close(cw->fd);
   }
}

static void sigint_cb(EV_P_ ev_signal *w, int revents) {
   ev_break(EV_A_ EVBREAK_ALL);
   printf("Signal caught, stopping loop.\n");
}
