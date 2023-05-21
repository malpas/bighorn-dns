cmake_minimum_required(VERSION 3.10)
project(bighorn_dns)

set(CMAKE_CXX_STANDARD 20)

find_package(asio CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)

enable_testing()

file(GLOB_RECURSE SRC_FILES src/*.cpp)
add_library(bighorn STATIC ${SRC_FILES})
target_include_directories(bighorn PUBLIC include)
target_include_directories(bighorn PRIVATE include/bighorn)
target_link_libraries(bighorn asio::asio)

file(GLOB TEST_FILES test/*.cpp)
add_executable(bighorn_test ${TEST_FILES})
target_link_libraries(bighorn_test GTest::gtest_main asio::asio bighorn)

include(GoogleTest)
gtest_discover_tests(bighorn_test)

if (MSVC)
    add_compile_options(/W4)
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()