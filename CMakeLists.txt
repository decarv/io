cmake_minimum_required(VERSION 3.14.0)

set(VERSION_MAJOR "0")
set(VERSION_MINOR "1")
set(VERSION_PATCH "0")
set(VERSION_STRING ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH})

#
# Avoid source tree pollution
#
set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

If(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not permitted. Make a separate folder for building:\nmkdir build; cd build; cmake ..\nBefore that, remove the files already created:\nrm -rf CMakeCache.txt CMakeFiles")
endif(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)

project(pgagroal_ev VERSION ${VERSION_STRING} LANGUAGES  C)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

message(STATUS "pgagroal_ev ${VERSION_STRING}")

include(CheckCCompilerFlag)
include(CheckCSourceCompiles)
include(CheckLinkerFlag)
include(FindPackageHandleStandardArgs)
include(GNUInstallDirs)

set(CMAKE_BUILD_TYPE "Release")

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Choose the type of build, options are: Debug Release Performance" FORCE)
endif ()

message(STATUS "Build type is ${CMAKE_BUILD_TYPE}")
message(STATUS "System is ${CMAKE_SYSTEM_NAME}")

set(SUPPORTED_COMPILERS "GNU" "Clang" "AppleClang")

# Check for a supported compiler
if (NOT CMAKE_C_COMPILER_ID IN_LIST SUPPORTED_COMPILERS)
    message(FATAL_ERROR "Unsupported compiler ${CMAKE_C_COMPILER_ID}. Supported compilers are: ${SUPPORTED_COMPILERS}")
endif ()

CHECK_C_COMPILER_FLAG("-std=c17" COMPILER_SUPPORTS_C17)
if(NOT COMPILER_SUPPORTS_C17)
    message(FATAL_ERROR "The compiler ${CMAKE_C_COMPILER} has no C17 support. Please use a different C compiler.")
endif()

option(USE_EPOLL "Use epoll as the backend instead of io_uring" OFF)

find_package(liburing 2.5)
if (LIBURING_FOUND AND NOT USE_EPOLL)
    message(STATUS "Backend set to io_uring.")
    set(BACKEND_SRC src/ev_io_uring.c)
    include_directories(${LIBURING_INCLUDE_DIRS} ${CMAKE_SOURCE_DIR}/include)
else ()
    message(STATUS "Backend set to epoll.")
    add_definitions(-DUSE_EPOLL)
    set(BACKEND_SRC "src/ev_epoll.c")
    include_directories(${CMAKE_SOURCE_DIR}/include)
    option(USE_EPOLL ON)
endif()

set(SOURCE_FILES ${BACKEND_SRC})
add_library(pgagroal_ev STATIC ${SOURCE_FILES})

# link luring
#if (LIBURING_FOUND)
#    target_link_libraries(pgagroal_ev ${LIBURING_LIBRARIES})
#endif()

install(TARGETS pgagroal_ev DESTINATION ${CMAKE_BINARY_DIR})

message(STATUS "pgagroal_ev built correctly.")

# enable and run tests

enable_testing()

add_subdirectory(test)

