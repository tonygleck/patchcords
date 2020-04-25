#Licensed under the MIT license. See LICENSE file in the project root for full license information.

function(add_unittest_directory test_directory)
    if (${patchcords_ut})
        add_subdirectory(${test_directory})
    endif()
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
    else()
        find_program(MEMORYCHECK_COMMAND valgrind)
        set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full" )
    endif()

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
