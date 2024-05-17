cmake_minimum_required(VERSION 3.28)
project(main C)

set(CMAKE_C_STANDARD 23)

add_executable(main main.c)

include_directories(./liburing/src/include/)
link_directories(./liburing/src/)
target_link_libraries(main uring)

target_compile_options(
        main PRIVATE -Wall
#        -O2
        -D_GNU_SOURCE
)
