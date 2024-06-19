//
// Created by decarv on 6/17/24.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "../include/io.h"

#define MAX_EVENTS 10
