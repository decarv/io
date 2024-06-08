echo "Building test_libev"
gcc -o test_libev test_libev.c -lev
gcc -o io_test_accept io_test_accept.c ../utils.c ../io.c -lev -luring
