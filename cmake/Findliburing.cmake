find_path(LIBURING_INCLUDE_DIR
        NAMES liburing.h
        PATHS /usr/include /usr/local/include
)

find_library(LIBURING_LIBRARY
        NAMES uring
        PATHS /usr/lib /usr/local/lib /usr/lib64/
)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(liburing DEFAULT_MSG LIBURING_LIBRARY LIBURING_INCLUDE_DIR)

if(LIBURING_FOUND)
    set(LIBURING_LIBRARIES ${LIBURING_LIBRARY})
    set(LIBURING_INCLUDE_DIRS ${LIBURING_INCLUDE_DIR})
endif()
