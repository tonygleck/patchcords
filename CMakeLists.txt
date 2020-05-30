#Licensed under the MIT license. See LICENSE file in the project root for full license information.

cmake_minimum_required(VERSION 3.5)

#Use solution folders.
set_property(GLOBAL PROPERTY USE_FOLDERS ON)
project(patchcords)

option(patchcords_ut "Include unittest in build" OFF)
option(patchcords_samples "Include samples in build" OFF)
option(enable_tls_lib   "Turn on the TLS libraries" ON)

if (CMAKE_BUILD_TYPE MATCHES "Debug" AND NOT WIN32)
    set(DEBUG_CONFIG ON)
    set(ENABLE_COVERAGE ON)
else()
    set(ENABLE_COVERAGE OFF)
    set(DEBUG_CONFIG OFF)
endif()

include("${CMAKE_CURRENT_LIST_DIR}/cmake_configs/proj_config.cmake")

if ((NOT TARGET azure_macro_utils_c) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/azure-macro-utils-c/CMakeLists.txt))
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/deps/azure-macro-utils-c)
    include_directories(${MACRO_UTILS_INC_FOLDER})
endif()
if (NOT TARGET umock_c)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/deps/umock-c)
    include_directories(${UMOCK_C_INC_FOLDER})
endif()
if (NOT TARGET lib-util-c)
    add_subdirectory(${CMAKE_CURRENT_LIST_DIR}/deps/lib-util-c)
    include_directories(${CMAKE_CURRENT_LIST_DIR}/deps/lib-util-c/inc/)
endif()

include_directories(${CMAKE_CURRENT_LIST_DIR}/inc)

#these are the C source files
set(source_c_files
    ./src/socket_debug_shim.c
    ./src/patchcord_client.c
)

#these are the C headers
set(source_h_files
    ./inc/patchcords/socket_debug_shim.h
    ./inc/patchcords/patchcord_client.h
)

#this is the product (a library)
add_library(patchcords ${source_c_files} ${source_h_files})
addCompileSettings(patchcords)
compileTargetAsC99(patchcords)

# Berkley socket library
set(socket_h_files
    ./inc/patchcords/cord_socket_client.h
)
set(socket_lib)
set(dependent_libs)
if (WIN32)
    set(socket_c_files
        ./src/cord_client_winsock.c
    )
    set(socket_lib cord_winsock)
    set(dependent_libs ws2_32)
endif()
if (UNIX)
    set(socket_c_files
        ./src/cord_client_berkley.c
    )
    set(socket_lib cord_berkley)
endif()
add_library(${socket_lib} ${socket_c_files} ${socket_h_files})
target_link_libraries(${socket_lib} patchcords lib-util-c ${dependent_libs})

addCompileSettings(${socket_lib})
compileTargetAsC99(${socket_lib})

if (${enable_tls_lib})
    set(tls_c_files
        ./src/cord_client_openssl.c
    )
    set(tls_h_files
    ./inc/patchcords/cord_tls_client.h
    )
    add_library(cord_openssl ${tls_c_files} ${tls_h_files})
    target_link_libraries(cord_openssl patchcords lib-util-c ssl crypto)
endif()

if (${patchcords_ut})
    enable_testing()
    include (CTest)

    include("${CMAKE_CURRENT_LIST_DIR}/cmake_configs/proj_testing.cmake")

    enable_coverage_testing()
    if ((NOT TARGET ctest) AND (EXISTS ${CMAKE_CURRENT_LIST_DIR}/deps/azure-ctest/CMakeLists.txt))
        add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/deps/azure-ctest)
        include_directories(${CTEST_INC_FOLDER})
    endif()

    add_subdirectory(${CMAKE_CURRENT_SOURCE_DIR}/tests)
endif()

if (${patchcords_samples})
    add_subdirectory(samples)
endif()
