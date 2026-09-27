# Builds the C++ tests and example against a prebuilt libmini_waf:
#
#     cargo build --release -p mini-waf-ffi
#     cmake -S cpp -B target/cpp && cmake --build target/cpp
#     ctest --test-dir target/cpp --output-on-failure

cmake_minimum_required(VERSION 3.25)
project(mini_waf_cpp LANGUAGES CXX)

# mini_waf.hpp wraps mini_waf.h, so both include directories are needed.
include(../c/cmake/MiniWafLibrary.cmake)
mini_waf_import_library(mini_waf::mini_waf_cpp
    "${CMAKE_CURRENT_SOURCE_DIR}/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/../c/include")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Threads REQUIRED)

# Catch2 is only needed by the tests; SYSTEM keeps its headers out of -Werror.
include(FetchContent)
FetchContent_Declare(Catch2
    GIT_REPOSITORY https://github.com/catchorg/Catch2.git
    GIT_TAG v3.9.1
    GIT_SHALLOW TRUE
    SYSTEM)
FetchContent_MakeAvailable(Catch2)
list(APPEND CMAKE_MODULE_PATH "${catch2_SOURCE_DIR}/extras")
include(Catch)

if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(protect examples/protect.cpp)
mini_waf_link(protect mini_waf::mini_waf_cpp)

add_executable(bench examples/bench.cpp)
mini_waf_link(bench mini_waf::mini_waf_cpp)

enable_testing()
add_executable(test_mini_waf tests/test_mini_waf.cpp)
# Linked first so the DLL is in place when Catch2 lists the tests.
mini_waf_link(test_mini_waf mini_waf::mini_waf_cpp)
target_link_libraries(test_mini_waf
    PRIVATE Catch2::Catch2WithMain Threads::Threads)
catch_discover_tests(test_mini_waf)
