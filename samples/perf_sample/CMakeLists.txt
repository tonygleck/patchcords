cmake_minimum_required(VERSION 3.3.0)

set(perf_client_files
    perf_client.c
)

add_executable(perf_client ${perf_client_files})
target_link_libraries(perf_client patchcords lib-util-c)

set(perf_server_files
    perf_server.c
)

add_executable(perf_server ${perf_server_files})
target_link_libraries(perf_server patchcords lib-util-c)

if (UNIX)
    target_link_libraries(perf_client cord_berkley)
    target_link_libraries(perf_server cord_berkley)
elseif(WIN32)
    target_link_libraries(perf_client cord_winsock)
    target_link_libraries(perf_server cord_winsock)
endif (UNIX)