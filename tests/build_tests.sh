echo "Building test_libev"
gcc -o out/test_libev test_libev.c -lev
gcc -o out/io_test_accept io_test_accept.c ../utils.c ../io.c -lev -luring
gcc -o out/server server.c