
set(tls_client_listener_files
    tls_client_listener.c
)

add_executable(tls_client_listener ${tls_client_listener_files})

target_link_libraries(tls_client_listener patchcords lib-util-c)

if(WIN32)
    target_link_libraries(tls_client_listener cord_winsock cord_schannel)
else()
    target_link_libraries(tls_client_listener cord_berkley cord_openssl)
endif(WIN32)
