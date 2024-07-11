
#include "../include/ev.h"
#include "utils.h"

//int
//proxy_receive_callback(void *data, int recv_fd, int err, void* buf, size_t buf_len)
//{
//   struct connection *conn = (struct connection*) data;
//   struct ev *ev = conn->ev;
//   int send_fd;
//
//   if (recv_fd == conn->client_fd)
//   {
//      send_fd = conn->server_fd;
//   }
//   else
//   {
//      send_fd = conn->client_fd;
//   }
//
//   union event_cb callback = { .io = NULL };
//   io_send_init(ev, send_fd, callback.io, buf, (int)buf_len, 0);
//   return 0;
//}
//
//int
//proxy_accept_callback(void *data, int client_fd, int err, void* buf, size_t buf_len)
//{
//   struct sockaddr_in client_addr;
//   socklen_t client_len = sizeof(client_addr);
//   struct connection *conn = (struct connection *)data;
//
//   if (client_fd < 0)
//   {
//      if (errno == EAGAIN || errno == EWOULDBLOCK)
//      {
//         exit(1);
//      }
//      perror("accept failed");
//      errors++;
//   }
//
//   pid_t pid = fork();
//   if (!pid)
//   {
//      int conn_fd = prepare_out_socket(server_in_port);
//      struct connection *conn_child = malloc(sizeof(struct connection));
//      ev_init(&conn_child->ev, conn_child, (struct ev_setup_opts){0});
//      conn_child->client_fd = client_fd;
//      conn_child->server_fd = conn_fd;
//      io_receive_init(conn_child->ev, client_fd, proxy_receive_callback);
//   }
//
//   return 0;
//}
//
//void*
//proxy_thread(void *p)
//{
//   int ret;
//   struct connection * conn = malloc(sizeof(struct connection));
//   ret = ev_init(&conn->ev, conn, (struct ev_setup_opts){0});
//   if (ret)
//   {
//      perror("ev_init");
//      return NULL;
//   }
//
//   int accept_fd = prepare_in_socket(proxy_in_port);
//   ret = io_accept_init(conn->ev, accept_fd, (io_cb) proxy_accept_callback);
//   if (ret)
//   {
//      perror("io_accept_init");
//      return NULL;
//   }
//
//   return 0;
//}
//
//int
//main(void)
//{
//   int ret;
//   struct connection *conn = malloc(sizeof(struct connection));
//   struct io *main_io = NULL;
//   int events;
//   int listening_socket;
//   int server_fd;
//
//   ret = io_context_setup((struct io_configuration_options) {0});
//   if (ret)
//   {
//      fprintf(stderr, "io_context_setup\n");
//      return 1;
//   }
//
//   ret = ev_init(&main_io, (void*) conn);
//   if (ret)
//   {
//      fprintf(stderr, "io_connection_setup\n");
//      return 1;
//   }
//
//   conn->io = main_io;
//
//   listening_socket = prepare_in_socket("8800");
//   server_fd = prepare_out_socket("8801");
//
//   conn->server_fd = server_fd;
//
//   register_event(main_io, listening_socket, ACCEPT, (event_cb) accept_cb, NULL, 0);
//   ev_loop(main_io);
//
//   return 0;
//}
//
