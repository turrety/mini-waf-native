# Builds the C tests and example against a prebuilt libmini_waf:
#
#     cargo build --release -p mini-waf-ffi
#     cmake -S c -B target/c && cmake --build target/c
#     ctest --test-dir target/c --output-on-failure

cmake_minimum_required(VERSION 3.18)
project(mini_waf_c LANGUAGES C)

include(cmake/MiniWafLibrary.cmake)
mini_waf_import_library(mini_waf::mini_waf "${CMAKE_CURRENT_SOURCE_DIR}/include")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(protect examples/protect.c)
mini_waf_link(protect mini_waf::mini_waf)

add_executable(bench examples/bench.c)
mini_waf_link(bench mini_waf::mini_waf)

enable_testing()
add_executable(test_mini_waf tests/test_mini_waf.c)
mini_waf_link(test_mini_waf mini_waf::mini_waf)
add_test(NAME test_mini_waf COMMAND test_mini_waf)
