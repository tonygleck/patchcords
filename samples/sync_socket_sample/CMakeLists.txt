cmake_minimum_required(VERSION 3.3.0)

set(socket_sample_files
    sync_socket_sample.c
)

add_executable(sync_socket_sample ${socket_sample_files})

target_link_libraries(sync_socket_sample patchcords lib-util-c)

if (UNIX)
    target_link_libraries(sync_socket_sample cord_berkley)
elseif(WIN32)
    target_link_libraries(sync_socket_sample cord_winsock)
endif (UNIX)