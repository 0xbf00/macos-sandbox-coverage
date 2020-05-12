cmake_minimum_required(VERSION 3.9)
project(sandbox_utils_tests)

set(TEST_TARGETS
    extension_test
    iokit_test
    nvram_test
    posix_sem_test
    posix_shm_test
    process_info_test
    signal_test
)

set(TEST_TARGETS ${TEST_TARGETS} PARENT_SCOPE)

set(CMAKE_BINARY_DIR ${CMAKE_BINARY_DIR}/bin/tests)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})

foreach(TEST_TARGET IN ITEMS ${TEST_TARGETS})
    add_executable(${TEST_TARGET} "${PROJECT_SOURCE_DIR}/${TEST_TARGET}.c")
    target_link_libraries(${TEST_TARGET} sandbox_utils)
endforeach()
