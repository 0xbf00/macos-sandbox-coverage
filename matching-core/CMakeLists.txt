cmake_minimum_required(VERSION 3.9)
project(matcher)

set(SRCS
    matcher.cpp
)

set(CMAKE_BINARY_DIR ${CMAKE_BINARY_DIR}/bin)
set(EXECUTABLE_OUTPUT_PATH ${CMAKE_BINARY_DIR})
set(LIBRARY_OUTPUT_PATH ${CMAKE_BINARY_DIR})

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -DDEBUG")

include_directories(
    "simbple/src/dependencies"
    "/usr/local/include"
)
add_subdirectory(sandbox_utils)
add_subdirectory(simbple/src/dependencies/sbpldump)

add_executable(${PROJECT_NAME} ${SRCS})

target_link_libraries(${PROJECT_NAME} sandbox_utils sbpldump)
