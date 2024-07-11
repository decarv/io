cmake_minimum_required(VERSION 3.14.0)

project(pgagroal_ev_tests LANGUAGES C)

cmake_policy(SET CMP0110 NEW)

enable_testing()

set(BIN_DIR ${CMAKE_BINARY_DIR}/test)
file(MAKE_DIRECTORY ${BIN_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include ${LIBURING_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/test)

add_executable(test_periodic test_periodic.c)
target_link_libraries(test_periodic PRIVATE pgagroal_ev uring)
set_target_properties(test_periodic PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(test_signals test_signals.c)
target_link_libraries(test_signals PRIVATE pgagroal_ev uring)
set_target_properties(test_signals PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(test_io test_io.c)
target_link_libraries(test_io PRIVATE pgagroal_ev uring)
set_target_properties(test_io PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

if(USE_EPOLL)
	message(STATUS "Starting epoll tests...")
else()
	message(STATUS "Starting io_uring tests...")
endif()
add_test(NAME "Periodic Test" COMMAND test_periodic)
add_test(NAME "Signal Test" COMMAND test_signals)
add_test(NAME "IO Test" COMMAND test_io)

# Uncomment
# add_executable(test_io_server test_io_server.c)
# target_link_libraries(test_io_server PRIVATE pgagroal_ev uring)
# set_target_properties(test_io_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})
# add_test(NAME "[io_uring] Server Test" COMMAND test_io_server)
# add_executable(test_io_proxy test_io_proxy.c)
# target_link_libraries(test_io_proxy PRIVATE pgagroal_ev uring)
# set_target_properties(test_io_proxy PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})
# add_test(NAME "[io_uring] Proxy Test" COMMAND test_io_proxy)
# add_executable(test_io_client test_io_client.c)
# target_link_libraries(test_io_client PRIVATE pgagroal_ev uring)
# set_target_properties(test_io_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})
# add_test(NAME "[io_uring] Client Test" COMMAND test_io_client)

message(STATUS "All tests built successfully.")
