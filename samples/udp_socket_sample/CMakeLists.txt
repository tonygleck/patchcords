
set(socket_sample_files
    udp_socket_sample.c
)

add_executable(udp_socket_sample ${socket_sample_files})

target_link_libraries(udp_socket_sample patchcords lib-util-c)

if (UNIX)
    target_link_libraries(udp_socket_sample cord_berkley)
elseif(WIN32)
    target_link_libraries(udp_socket_sample cord_winsock)
endif (UNIX)
