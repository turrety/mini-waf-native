# Builds the C tests and example against a prebuilt libmini_waf:
#
#     cargo build --release -p mini-waf-ffi
#     cmake -S c -B target/c && cmake --build target/c
#     ctest --test-dir target/c --output-on-failure

cmake_minimum_required(VERSION 3.18)
project(mini_waf_c LANGUAGES C)

set(MINI_WAF_LIBRARY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../target/release"
    CACHE PATH "Directory holding libmini_waf")
find_library(MINI_WAF_LIBRARY
    NAMES mini_waf mini_waf.dll
    PATHS "${MINI_WAF_LIBRARY_DIR}"
    NO_DEFAULT_PATH
    REQUIRED)

add_library(mini_waf::mini_waf UNKNOWN IMPORTED)
set_target_properties(mini_waf::mini_waf PROPERTIES
    IMPORTED_LOCATION "${MINI_WAF_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include")

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(protect examples/protect.c)
target_link_libraries(protect PRIVATE mini_waf::mini_waf)

add_executable(bench examples/bench.c)
target_link_libraries(bench PRIVATE mini_waf::mini_waf)

enable_testing()
add_executable(test_mini_waf tests/test_mini_waf.c)
target_link_libraries(test_mini_waf PRIVATE mini_waf::mini_waf)
add_test(NAME test_mini_waf COMMAND test_mini_waf)
