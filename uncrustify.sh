#!/bin/bash

function indent()
{
    for f in $1
    do
        uncrustify -c uncrustify.cfg -q --replace --no-backup $f
    done
}

indent "*.c"
indent "*.h"
indent "src/*.c"
indent "src/include/*.h"
indent "src/libpgagroal/*.c"
indent "test/*.c"
