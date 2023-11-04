cmake_minimum_required(VERSION 3.10)
project(bighorn)

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

add_library(bighorn STATIC
        src/data.cpp
        src/error.cpp
        src/lookup.cpp
        src/resolver.cpp
        src/static_lookup.cpp)
set_property(TARGET bighorn PROPERTY CXX_STANDARD 20)
target_include_directories(bighorn PUBLIC include)
target_include_directories(bighorn PRIVATE include/bighorn)
if (NOT WIN32)
    target_link_libraries(bighorn PRIVATE asio::asio)
else ()
    target_link_libraries(bighorn PRIVATE asio::asio ws2_32)
endif ()

add_executable(bighorn_test
    test/test_byte_output.cpp
    test/test_input.cpp
    test/test_pointer.cpp
    test/test_resolution.cpp
    test/test_responder.cpp
    test/test_standard_queries.cpp
    test/test_unreliable_server.cpp
    test/test_wildcard.cpp)
set_property(TARGET bighorn_test PROPERTY CXX_STANDARD 20)
target_link_libraries(bighorn_test PRIVATE GTest::gtest_main GTest::gmock_main asio::asio bighorn)

add_executable(bighorn_example_basic examples/udp_basic.cpp)
set_property(TARGET bighorn_example_basic PROPERTY CXX_STANDARD 20)
target_link_libraries(bighorn_example_basic PRIVATE argparse::argparse bighorn asio::asio)

add_executable(bighorn_example_recursive examples/udp_recursive.cpp)
set_property(TARGET bighorn_example_recursive PROPERTY CXX_STANDARD 20)
target_link_libraries(bighorn_example_recursive PRIVATE bighorn asio::asio)

include(GoogleTest)
gtest_discover_tests(bighorn_test)
