
set(tls_client_sample_files
tls_client_sample.c
)

add_executable(tls_client_sample ${tls_client_sample_files})

target_link_libraries(tls_client_sample patchcords lib-util-c)

if(WIN32)
    target_link_libraries(tls_client_sample cord_winsock cord_schannel)
else()
    target_link_libraries(tls_client_sample cord_berkley cord_openssl)
endif(WIN32)
