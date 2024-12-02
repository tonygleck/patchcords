
set(socket_listener_files
    socket_listener.c
)

add_executable(socket_listener ${socket_listener_files})

target_link_libraries(socket_listener patchcords lib-util-c)

if (UNIX)
    target_link_libraries(socket_listener cord_berkley)
elseif(WIN32)
    target_link_libraries(socket_listener cord_winsock)
endif (UNIX)
