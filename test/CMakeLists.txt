set(BIN_DIR ${CMAKE_BINARY_DIR}/test)

file(MAKE_DIRECTORY ${BIN_DIR})

include_directories(${CMAKE_SOURCE_DIR}/include ${LIBURING_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/test)

set(SOURCE_FILES ${CMAKE_SOURCE_DIR}/test)

#add_executable(test_io_server test_io_server.c)
#target_link_libraries(test_io_server PRIVATE pgagroal_ev uring)
#set_target_properties(test_io_server PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})
#
#add_executable(test_io_proxy test_io_proxy.c)
#target_link_libraries(test_io_proxy PRIVATE pgagroal_ev uring)
#set_target_properties(test_io_proxy PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})
#
#add_executable(test_io_client test_io_client.c)
#target_link_libraries(test_io_client PRIVATE pgagroal_ev uring)
#set_target_properties(test_io_client PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(test_periodic test_periodic.c)
target_link_libraries(test_periodic PRIVATE pgagroal_ev uring)
set_target_properties(test_periodic PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

add_executable(test_signals test_signals.c)
target_link_libraries(test_signals PRIVATE pgagroal_ev uring)
set_target_properties(test_signals PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${BIN_DIR})

message(STATUS "All tests built successfully.")
