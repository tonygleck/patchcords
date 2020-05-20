#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.3.0)

add_unittest_directory(patchcord_client_e2e)
add_unittest_directory(patchcord_client_ut)
if (WIN32)
    add_unittest_directory(patchcord_client_winsock_ut)
endif()
if (UNIX)
    add_unittest_directory(cord_client_berkley_ut)
endif()
if (${enable_tls_lib})
    add_unittest_directory(cord_client_openssl_ut)
endif()
