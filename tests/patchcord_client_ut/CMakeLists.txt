#Licensed under the MIT license. See LICENSE file in the project root for full license information.

compileAsC11()

set(theseTestsName patchcord_client_ut)

set(${theseTestsName}_test_files
    ${theseTestsName}.c
)

set(${theseTestsName}_c_files
    ../../src/patchcord_client.c
)

set(${theseTestsName}_h_files
)

build_test_project(${theseTestsName} "tests/patchcord_tests")
