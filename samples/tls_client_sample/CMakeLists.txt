cmake_minimum_required(VERSION 3.3.0)

set(tls_client_sample_files
tls_client_sample.c
)

add_executable(tls_client_sample ${tls_client_sample_files})

target_link_libraries(tls_client_sample patchcords cord_openssl lib-util-c)

if (UNIX)
    target_link_libraries(tls_client_sample cord_berkley)
elseif(WIN32)
    target_link_libraries(tls_client_sample cord_winsock)
endif (UNIX)