#Licensed under the MIT license. See LICENSE file in the project root for full license information.

compileAsC11()

set(theseTestsName cord_client_berkley_ut)

set(${theseTestsName}_test_files
    ${theseTestsName}.c
)

set(${theseTestsName}_c_files
    ../../src/cord_client_berkley.c
)

set(${theseTestsName}_h_files
)

add_definitions(-DUSE_SOCKET_DEBUG_SHIM)

build_test_project(${theseTestsName} "tests/patchcord_tests")
