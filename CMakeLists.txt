cmake_minimum_required(VERSION 3.10)
project(bighorn)

set(CMAKE_CXX_STANDARD 20)

find_package(asio CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
find_package(argparse CONFIG REQUIRED)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

if (MSVC)
    add_compile_options(/W4)
else ()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif ()

enable_testing()

file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_library(bighorn STATIC ${SRC_FILES})
target_include_directories(bighorn PUBLIC include)
target_include_directories(bighorn PRIVATE include/bighorn)
if (NOT WIN32)
    target_link_libraries(bighorn PRIVATE asio::asio)
else ()
    target_link_libraries(bighorn PRIVATE asio::asio ws2_32)
endif ()

file(GLOB TEST_FILES test/*.cpp test/*.h)
add_executable(bighorn_test ${TEST_FILES})
target_link_libraries(bighorn_test PRIVATE GTest::gtest_main GTest::gmock_main asio::asio bighorn)

file(GLOB EXAMPLE_FILES examples/udp_basic.cpp)
add_executable(bighorn_example_basic ${EXAMPLE_FILES})
target_link_libraries(bighorn_example_basic PRIVATE argparse::argparse bighorn asio::asio)

file(GLOB EXAMPLE_FILES examples/udp_recursive.cpp)
add_executable(bighorn_example_recursive ${EXAMPLE_FILES})
target_link_libraries(bighorn_example_recursive PRIVATE bighorn asio::asio)

include(GoogleTest)
gtest_discover_tests(bighorn_test)
