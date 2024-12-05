#Licensed under the MIT license. See LICENSE file in the project root for full license information.

compileAsC11()

set(theseTestsName cord_client_winsock_ut)

set(${theseTestsName}_test_files
    ${theseTestsName}.c
)

set(${theseTestsName}_c_files
    ../../src/cord_client_winsock.c
)

set(${theseTestsName}_h_files
)

build_test_project(${theseTestsName} "tests/patchcord_tests")
add_definitions(-DUSE_SOCKET_DEBUG_SHIM)
