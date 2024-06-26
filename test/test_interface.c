/**
 * The idea of this test is to have three threads.
 * A server, receiving the data and counting the rcvd data.
 * A bidirectional proxy.
 * A client, sending the data and counting the sent data.
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <string.h>

#include "../include/ev.h"
#include "utils.h"

static int recv_bytes = 0;
static int sent_bytes = 0;


int
server_thread()
{
   return 0;
}

int
proxy_thread()
{
   return 0;
}

int
client_thread()
{
   return 0;
}

int main(int argc, char* argv[])
{
   pthread_t server, proxy, client;





   assert(sent_bytes == recv_bytes);
}
