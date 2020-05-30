cmake_minimum_required(VERSION 3.3.0)

set(tls_client_listener_files
    tls_client_listener.c
)

add_executable(tls_client_listener ${tls_client_listener_files})

target_link_libraries(tls_client_listener patchcords cord_openssl lib-util-c)

if (UNIX)
    target_link_libraries(tls_client_listener cord_berkley)
elseif(WIN32)
    target_link_libraries(tls_client_listener cord_winsock)
endif (UNIX)
