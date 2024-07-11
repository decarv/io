# ev

## Building and Testing

### Build io_uring backend
From root directory:
```shell
mkdir build
cd build
cmake ..
make
ctest
```

### Build epoll backend
From root directory:
```shell
mkdir build
cd build
cmake .. -DUSE_EPOLL=ON
make
ctest
```
