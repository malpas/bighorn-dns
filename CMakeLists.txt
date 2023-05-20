cmake_minimum_required(VERSION 3.10)
project(bighorn_dns)

set(CMAKE_CXX_STANDARD 20)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/03597a01ee50ed33e9dfd640b249b4be3799d395.zip
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

file(GLOB_RECURSE SRC_FILES src/*)
add_library(bighorn STATIC ${SRC_FILES})
target_include_directories(bighorn PUBLIC include)
target_include_directories(bighorn PRIVATE include/bighorn)

file(GLOB TEST_FILES test/*.cpp)
add_executable(bighorn_test ${TEST_FILES})
target_link_libraries(bighorn_test GTest::gtest_main bighorn)

include(GoogleTest)
gtest_discover_tests(bighorn_test)