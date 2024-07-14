# ev

This project is part of the Google Summer of Code for the pgagroal project.

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

## Architecture

 event handling interface
  1. ev_init: init the event handling context
  2. {signal|periodic|io}_init: returns an fd
  3. ev_register_{signal|periodic|io}: registers the file descriptor

