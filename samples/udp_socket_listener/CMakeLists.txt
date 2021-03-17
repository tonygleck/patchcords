cmake_minimum_required(VERSION 3.3.0)

set(socket_listener_files
    udp_socket_listener.c
)

add_executable(udp_socket_listener ${socket_listener_files})

target_link_libraries(udp_socket_listener patchcords lib-util-c)

if (UNIX)
    target_link_libraries(udp_socket_listener cord_berkley)
elseif(WIN32)
    target_link_libraries(udp_socket_listener cord_winsock)
endif (UNIX)
