cmake_minimum_required(VERSION 3.3.0)

set(socket_sample_files
    socket_sample.c
)

add_executable(socket_sample ${socket_sample_files})

target_link_libraries(socket_sample patchcords lib-util-c)

if (UNIX)
    target_link_libraries(socket_sample cord_berkley)
endif (UNIX)