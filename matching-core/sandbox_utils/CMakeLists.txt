cmake_minimum_required(VERSION 3.9)
project(sandbox_utils)

set(SANDBOX_UTILS_SRCS
    posix_shm.c
    mach.c
    iokit.c
    posix_sem.c
    nvram.c
    signal.c
    file.c
    process_info.c
    sandbox_utils.c
)

set(CMAKE_BINARY_DIR ${CMAKE_BINARY_DIR}/bin)
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O3")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -DDEBUG")

add_library(${PROJECT_NAME} SHARED ${SANDBOX_UTILS_SRCS})

target_link_libraries(${PROJECT_NAME}
    "-framework CoreFoundation"
    "-framework IOKit"
)

add_subdirectory(tests)

enable_testing()
foreach(TEST_TARGET IN ITEMS ${TEST_TARGETS})
    add_test(NAME ${TEST_TARGET} COMMAND ${TEST_TARGET})
endforeach()
