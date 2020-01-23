#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.3.0)

add_unittest_directory(xio_client_ut)
if (WIN32)
    add_unittest_directory(xio_client_winsock_ut)
endif()
if (UNIX)
    add_unittest_directory(xio_client_berkley_ut)
endif()
