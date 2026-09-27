# Imports the prebuilt libmini_waf as a shared library target, the same way
# on every platform: libmini_waf.so / .dylib, or mini_waf.dll with its
# import library (mini_waf.dll.lib with MSVC, libmini_waf.dll.a with MinGW).
#
#     mini_waf_import_library(<target> <include directories>...)
#     mini_waf_link(<executable> <target>)

set(MINI_WAF_LIBRARY_DIR "${CMAKE_CURRENT_LIST_DIR}/../../target/release"
    CACHE PATH "Directory holding libmini_waf; relative to the repository")

function(mini_waf_import_library target)
    file(TO_CMAKE_PATH "${MINI_WAF_LIBRARY_DIR}" directory)
    get_filename_component(directory "${directory}" ABSOLUTE
        BASE_DIR "${CMAKE_CURRENT_FUNCTION_LIST_DIR}/../..")
    if(WIN32)
        find_file(MINI_WAF_RUNTIME mini_waf.dll
            PATHS "${directory}" NO_DEFAULT_PATH REQUIRED)
        find_library(MINI_WAF_IMPLIB NAMES mini_waf.dll
            PATHS "${directory}" NO_DEFAULT_PATH REQUIRED)
    else()
        find_library(MINI_WAF_RUNTIME NAMES mini_waf
            PATHS "${directory}" NO_DEFAULT_PATH REQUIRED)
    endif()
    add_library(${target} SHARED IMPORTED GLOBAL)
    set_target_properties(${target} PROPERTIES
        IMPORTED_LOCATION "${MINI_WAF_RUNTIME}"
        INTERFACE_INCLUDE_DIRECTORIES "${ARGN}")
    if(WIN32)
        set_target_properties(${target} PROPERTIES
            IMPORTED_IMPLIB "${MINI_WAF_IMPLIB}")
    endif()
endfunction()

# Link `executable` against the library; on Windows, also copy the DLL next
# to it, where the loader looks first.
function(mini_waf_link executable target)
    target_link_libraries(${executable} PRIVATE ${target})
    if(WIN32)
        add_custom_command(TARGET ${executable} POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:${target}>" "$<TARGET_FILE_DIR:${executable}>")
    endif()
endfunction()
