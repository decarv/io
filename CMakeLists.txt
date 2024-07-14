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

set(CMAKE_BUILD_TYPE "Debug")

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

#
# ev backend
#
option(USE_URING "Use either io_uring or epoll as Linux event handling backend" ON)
find_package(Liburing 2.5)
if (NOT LIBURING_FOUND)
        option(USE_URING OFF)
        message(STATUS "liburing found")
endif()

if (USE_URING)
  add_compile_options(-DUSE_URING=1)
  include_directories(${LIBURING_INCLUDE_DIRS})
  link_libraries(${LIBURING_LIBRARY})
  message(STATUS "pgagroal ev handling backend: io_uring")
else ()
  add_compile_options(-DUSE_URING=0)
  message(STATUS "pgagroal ev handling backend: epoll")
endif()

set(SOURCE_FILES "src/ev.c")
add_library(pgagroal_ev STATIC ${SOURCE_FILES})
include_directories("include/")

target_compile_options(pgagroal_ev PRIVATE -g)
target_compile_options(pgagroal_ev PRIVATE -O0)

install(TARGETS pgagroal_ev DESTINATION ${CMAKE_BINARY_DIR})

message(STATUS "pgagroal_ev built correctly.")

# enable and run tests

enable_testing()

add_subdirectory(test)

