// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "lib-util-c/thread_mgr.h"

#include "patchcords/patchcord_client.h"
#include "patchcords/cord_socket_client.h"
#include "patchcords/cord_tls_client.h"

typedef struct SAMPLE_DATA_TAG
{
    int keep_running;
    int socket_open;
    int socket_closed;
    int send_complete;
    PATCH_INSTANCE_HANDLE incoming_socket;
} SAMPLE_DATA;

static const char* HOSTNAME = "127.0.0.1";
static const uint16_t PORT_VALUE = 4433;
static const char* TEST_SEND_DATA = "This is a test message\n";

void on_xio_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    SAMPLE_DATA* sample = (SAMPLE_DATA*)context;
    if (open_result != IO_OPEN_OK)
    {
        sample->keep_running = 1;
        printf("Open failed\n");
    }
    else
    {
        sample->socket_open = 1;
        printf("Open complete called");
    }
}

static void on_xio_close_complete(void* context)
{
    SAMPLE_DATA* sample = (SAMPLE_DATA*)context;
    sample->socket_closed = 1;
}

void on_xio_send_complete(void* context, IO_SEND_RESULT send_result)
{
    SAMPLE_DATA* sample = (SAMPLE_DATA*)context;
    sample->send_complete = 2;
}

void on_xio_bytes_recv(void* context, const unsigned char* buffer, size_t size)
{

}

void on_xio_error(void* context, IO_ERROR_RESULT error_result)
{
    printf("Error detected\n");
}

void on_accept_conn(void* context, const void* config)
{
    const SOCKETIO_CONFIG* socket_config = (const SOCKETIO_CONFIG*)config;
    SAMPLE_DATA* sample = (SAMPLE_DATA*)context;
    PATCHCORD_CALLBACK_INFO client_info;
    client_info.on_bytes_received = on_xio_bytes_recv;
    client_info.on_bytes_received_ctx = sample;
    client_info.on_io_error = on_xio_error;
    client_info.on_io_error_ctx = sample;
    if ((sample->incoming_socket = patchcord_client_create(cord_tls_get_tls_interface(), config, &client_info)) == NULL)
    {
        printf("Failure connecting incoming socket");
    }
}

static char* open_file_data(const char* filename)
{
    char* result = NULL;
    FILE* fd;
    if ((fd = fopen(filename, "rb") ) != NULL)
    {
            // obtain file size:
        fseek(fd , 0 , SEEK_END);
        long file_size = ftell(fd);
        rewind(fd);

        if ((result = malloc(sizeof(char)*file_size)) != NULL)
        {
            size_t read_size = fread(result, 1, file_size, fd);
            if (read_size != (size_t)file_size)
            {
                printf("failure reader size");
                free(result);
                result = NULL;
            }
        }
        else
        {
            printf("failure allocating file data");
        }
        fclose(fd);
    }
    else
    {
        printf("failure to open the file");
    }
    return result;
}

int main()
{
    TLS_CONFIG tls_config = {0};
    SAMPLE_DATA data = {0};
    SOCKETIO_CONFIG config = {0};
    PATCHCORD_CALLBACK_INFO client_info = {0};

    char* server_cert = NULL;
    const char* server_cert_path = getenv("SERVER_CERTIFICATE");
    if (server_cert_path != NULL && (server_cert = open_file_data(server_cert_path)) == NULL)
    {
        printf("Failed getting server cert");
    }
    else
    {
        tls_config.hostname = config.hostname = HOSTNAME;
        tls_config.port = config.port = PORT_VALUE;
        config.address_type = ADDRESS_TYPE_IP;

        tls_config.socket_config = &config;
        tls_config.socket_desc = cord_socket_get_interface();
        tls_config.server_certifiate = getenv("SERVER_CERTIFICATE");

        client_info.on_bytes_received = on_xio_bytes_recv;
        client_info.on_bytes_received_ctx = &data;
        client_info.on_io_error = on_xio_error;
        client_info.on_io_error_ctx = &data;
        PATCH_INSTANCE_HANDLE xio_handle = patchcord_client_create(cord_tls_get_tls_interface(), &config, &client_info);
        if (xio_handle == NULL)
        {
            printf("Failure creating socket");
        }
        else
        {
            if (patchcord_client_listen(xio_handle, on_accept_conn, &data) != 0)
            {
                printf("Failed socket open");
            }
            else
            {
                do
                {
                    patchcord_client_process_item(xio_handle);

                    if (data.socket_open > 0)
                    {
                    }
                    if (data.socket_closed > 0)
                    {
                        break;
                    }
                    thread_mgr_sleep(5);
                } while (data.keep_running == 0);
            }
            patchcord_client_destroy(xio_handle);
        }
        free(server_cert);
    }
    return 0;
}