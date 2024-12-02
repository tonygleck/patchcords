#Licensed under the MIT license. See LICENSE file in the project root for full license information.

function(add_unittest_directory test_directory)
    if (${patchcords_ut})
        add_subdirectory(${test_directory})
    endif()
endfunction(add_unittest_directory)

function(add_inttest_directory test_directory)
    if (${patchcords_int})
        add_subdirectory(${test_directory})
    endif()
endfunction(add_inttest_directory)

function(build_dll_project whatIsBuilding folder)
    link_directories(${whatIsBuilding}_dll $ENV{VCInstallDir}UnitTest/lib)

    add_library(${whatIsBuilding}_dll SHARED
        ${${whatIsBuilding}_test_files}
        ${${whatIsBuilding}_cpp_files}
        ${${whatIsBuilding}_h_files}
        ${${whatIsBuilding}_c_files}
        ${logging_files}
    )

    set_target_properties(${whatIsBuilding}_dll
               PROPERTIES
               FOLDER ${folder})

    set_source_files_properties(${${whatIsBuilding}_c_files} ${logging_files}
               PROPERTIES
               COMPILE_FLAGS /TC)

    set_source_files_properties(${${whatIsBuilding}_cpp_files}
               PROPERTIES
               COMPILE_FLAGS /TP)

    target_link_libraries(${whatIsBuilding}_dll umock_c ctest)# testrunnerswitcher)# ${whatIsBuilding}_testsonly_lib)

    # set(PARSING_ADDITIONAL_LIBS OFF)
    # set(PARSING_VALGRIND_SUPPRESSIONS_FILE OFF)
    # set(VALGRIND_SUPPRESSIONS_FILE_EXTRA_PARAMETER)
    # set(ARG_PREFIX "none")
    # foreach(f ${ARGN})
    #     set(skip_to_next FALSE)
    #     if(${f} STREQUAL "ADDITIONAL_LIBS")
    #         SET(PARSING_ADDITIONAL_LIBS ON)
    #         SET(PARSING_VALGRIND_SUPPRESSIONS_FILE OFF)
    #         set(ARG_PREFIX "none")
    #         #also unset all the other states
    #         set(skip_to_next TRUE)
    #     elseif(${f} STREQUAL "VALGRIND_SUPPRESSIONS_FILE")
    #         SET(PARSING_ADDITIONAL_LIBS OFF)
    #         SET(PARSING_VALGRIND_SUPPRESSIONS_FILE ON)
    #         set(skip_to_next TRUE)
    #     endif()

    #     if(NOT skip_to_next)
    #         if(PARSING_ADDITIONAL_LIBS)
    #             if((${f} STREQUAL "debug") OR (${f} STREQUAL "optimized") OR (${f} STREQUAL "general"))
    #                 SET(ARG_PREFIX ${f})
    #             else()
    #                 target_link_libraries_with_arg_prefix(${ARG_PREFIX} ${whatIsBuilding}_dll ${f})
    #                 target_link_libraries_with_arg_prefix(${ARG_PREFIX} ${whatIsBuilding}_testsonly_lib ${f})
    #                 set(ARG_PREFIX "none")
    #             endif()
    #         endif()
    #     endif()

    # endforeach()

    # SET(SPACES " ")
    # SET(VAR 1)
    # foreach(file ${${whatIsBuilding}_test_files})
    #     # for x64 the underscore is not needed
    #     if (ARCHITECTURE STREQUAL "x86_64" OR ARCHITECTURE STREQUAL "ARM")
    #         set_property(TARGET ${whatIsBuilding}_dll APPEND_STRING PROPERTY LINK_FLAGS ${SPACES}/INCLUDE:"some_symbol_for_cppunittest_${VAR}")
    #     else()
    #         set_property(TARGET ${whatIsBuilding}_dll APPEND_STRING PROPERTY LINK_FLAGS ${SPACES}/INCLUDE:"_some_symbol_for_cppunittest_${VAR}")
    #     endif()
    #     MATH(EXPR VAR "${VAR}+1")
    # endforeach()

endfunction()

function(build_test_project whatIsBuilding folder)

    add_definitions(-DUSE_MEMORY_DEBUG_SHIM)

    set(test_include_dir ${MICROMOCK_INC_FOLDER} ${TESTRUNNERSWITCHER_INC_FOLDER} ${CTEST_INC_FOLDER} ${UMOCK_C_INC_FOLDER})
    set(logging_files ${CMAKE_SOURCE_DIR}/deps/lib-util-c/src/app_logging.c)
    include_directories(${CMAKE_SOURCE_DIR}/deps/lib-util-c)

    if (WIN32)
        add_definitions(-DUNICODE)
        add_definitions(-D_UNICODE)
        #windows needs this define
        add_definitions(-D_CRT_SECURE_NO_WARNINGS)

        # Only add dll projects for UnitTests
        if(("${whatIsBuilding}" MATCHES ".*ut.*"))
            build_dll_project(${whatIsBuilding} ${folder})
        endif()
    else()
        find_program(MEMORYCHECK_COMMAND valgrind)
        set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full" )
    endif()

    #add_library(${whatIsBuilding}_testsonly_lib STATIC
    #    ${${whatIsBuilding}_test_files}
    #)
    #SET(VAR 1)
    #foreach(file ${${whatIsBuilding}_test_files})
    #    set_source_files_properties(${file} PROPERTIES COMPILE_FLAGS -DCPPUNITTEST_SYMBOL=some_symbol_for_cppunittest_${VAR})
    #    MATH(EXPR VAR "${VAR}+1")
    #endforeach()

    #set_target_properties(${whatIsBuilding}_testsonly_lib
    #           PROPERTIES
    #           FOLDER ${folder} )

    #target_include_directories(${whatIsBuilding}_testsonly_lib PUBLIC ${test_include_dir} $ENV{VCInstallDir}UnitTest/include)
    #target_compile_definitions(${whatIsBuilding}_testsonly_lib PUBLIC -DCPP_UNITTEST)
    #target_compile_options(${whatIsBuilding}_testsonly_lib PUBLIC /TP /EHsc)

    add_executable(${whatIsBuilding}_exe
        ${${whatIsBuilding}_test_files}
        ${${whatIsBuilding}_cpp_files}
        ${${whatIsBuilding}_h_files}
        ${${whatIsBuilding}_c_files}
        ${CMAKE_CURRENT_LIST_DIR}/main.c
        ${logging_files}
    )

    compileTargetAsC99(${whatIsBuilding}_exe)

    set_target_properties(${whatIsBuilding}_exe
               PROPERTIES
               FOLDER ${folder})

    target_compile_definitions(${whatIsBuilding}_exe PUBLIC -DUSE_CTEST)
    target_include_directories(${whatIsBuilding}_exe PUBLIC ${test_include_dir})

    target_link_libraries(${whatIsBuilding}_exe umock_c ctest)
    if (WIN32)
    else()
        target_link_libraries(${whatIsBuilding}_exe m)
    endif()
    if (${ENABLE_COVERAGE})
        set_target_properties(${whatIsBuilding}_exe PROPERTIES COMPILE_FLAGS "-fprofile-arcs -ftest-coverage")
        target_link_libraries(${whatIsBuilding}_exe gcov)
        set(CMAKE_CXX_OUTPUT_EXTENSION_REPLACE 1)
    endif()

    add_test(NAME ${whatIsBuilding} COMMAND $<TARGET_FILE:${whatIsBuilding}_exe>)
endfunction()

function(enable_coverage_testing)
    if (${ENABLE_COVERAGE})
        find_program(GCOV_PATH gcov)
        if(NOT GCOV_PATH)
            message(FATAL_ERROR "gcov not found! Aborting...")
        endif() # NOT GCOV_PATH
    endif()
endfunction()
