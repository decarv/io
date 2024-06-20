BIN_DIR="./out"

echo "Building server"
gcc -I ../include -o out/test_io_server test_io_server.c

echo "Building test_libev"
gcc -I ../include -o out/test_libev test_libev.c -lev

echo "Building test_io_proxy"
gcc -I ../include -o out/test_io_proxy test_io_proxy.c ../src/utils.c ../src/io.c -lev -luring

echo "Building test_io_client"
gcc -I ../include -o out/test_io_client test_io_client.c ../src/utils.c -luring
echo "Built."

echo "Building test_io_client"
gcc -I ../include -o out/test_io_client test_io_client.c ../src/utils.c -luring
echo "Built."

echo "Building test_periodic"
gcc -I ../include -o out/test_periodic test_periodic.c ../src/utils.c ../src/periodic.c ../src/io.c -lev -luring
echo "Built."

echo "Building test_signals"
gcc -I ../include -o out/test_signals test_signals.c ../src/utils.c ../src/periodic.c ../src/io.c -lev -luring
echo "Built."

echo "Done."
