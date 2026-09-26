# Builds the C++ tests and example against a prebuilt libmini_waf:
#
#     cargo build --release -p mini-waf-ffi
#     cmake -S bindings/cpp -B target/cpp && cmake --build target/cpp
#     ctest --test-dir target/cpp --output-on-failure

cmake_minimum_required(VERSION 3.18)
project(mini_waf_cpp LANGUAGES CXX)

set(MINI_WAF_LIBRARY_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../../target/release"
    CACHE PATH "Directory holding libmini_waf")
find_library(MINI_WAF_LIBRARY
    NAMES mini_waf mini_waf.dll
    PATHS "${MINI_WAF_LIBRARY_DIR}"
    NO_DEFAULT_PATH
    REQUIRED)

# mini_waf.hpp wraps mini_waf.h, so both include directories are needed.
add_library(mini_waf::mini_waf_cpp UNKNOWN IMPORTED)
set_target_properties(mini_waf::mini_waf_cpp PROPERTIES
    IMPORTED_LOCATION "${MINI_WAF_LIBRARY}"
    INTERFACE_INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_SOURCE_DIR}/include;${CMAKE_CURRENT_SOURCE_DIR}/../c/include")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
find_package(Threads REQUIRED)
if(NOT MSVC)
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
endif()

add_executable(protect examples/protect.cpp)
target_link_libraries(protect PRIVATE mini_waf::mini_waf_cpp)

enable_testing()
add_executable(test_mini_waf tests/test_mini_waf.cpp)
target_link_libraries(test_mini_waf PRIVATE mini_waf::mini_waf_cpp Threads::Threads)
add_test(NAME test_mini_waf COMMAND test_mini_waf)
