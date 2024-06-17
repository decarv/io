BIN_DIR="./out"

echo "Building server"
gcc -o out/server server.c

echo "Building test_libev"
gcc -o out/test_libev test_libev.c -lev

echo "Building io_test_accept"
gcc -o out/io_test_accept io_test_accept.c ../src/utils.c ../src/io.c -lev -luring

echo "Building io_test_client"
gcc -o out/io_test_client io_test_client.c ../src/utils.c -luring

echo "Building io_test_client"
gcc -o out/io_test_client io_test_client.c ../src/utils.c -luring

echo "Building test_periodic"
gcc -o out/test_periodic test_periodic.c ../src/utils.c ../src/periodic.c ../src/io.c -lev -luring

echo "Done."
