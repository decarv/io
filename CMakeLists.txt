cmake_minimum_required(VERSION 3.28)
project(io C)

set(CMAKE_C_STANDARD 23)

add_executable(io io.c)

include_directories(./liburing/src/include/)
link_directories(./liburing/src/)
target_link_libraries(io uring)

target_compile_options(
        io PRIVATE -Wall
#        -O2
        -D_GNU_SOURCE
)
