//
// Created by decarv on 7/15/24.
//
#include "ev.h"

int main(void)
{
   event_cb nil = { 0 };
   printf("pos of ev_cb: %p\n", nil.io);
   return 0;
}