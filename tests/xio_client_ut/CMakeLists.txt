#Copyright (c) Microsoft. All rights reserved.
#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 2.8.11)

compileAsC11()

set(theseTestsName xio_client_ut)

set(${theseTestsName}_test_files
    ${theseTestsName}.c
)

set(${theseTestsName}_c_files
    ../../src/xio_client.c
)

set(${theseTestsName}_h_files
)

build_test_project(${theseTestsName} "tests/lib_utils_tests")
