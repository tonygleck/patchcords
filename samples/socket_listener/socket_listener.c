// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "patchcords/patchcord_client.h"
#include "patchcords/cord_socket_client.h"

typedef struct SAMPLE_DATA_TAG
{
    int keep_running;
    int operation_count;
    PATCH_INSTANCE_HANDLE incoming_socket;
} SAMPLE_DATA;

static const char* TEST_SEND_DATA = "This is a test message\n";

static void on_close_complete(void* context)
{
    SAMPLE_DATA* sample = (SAMPLE_DATA*)context;
    sample->operation_count++;
    printf("Client is closed\n");
}

static void on_bytes_recv(void* context, const unsigned char* buffer, size_t size, const void* config)
{
    (void)config;
    SAMPLE_DATA* sample = (SAMPLE_DATA*)context;
    printf("Recv data from socket: %.*s\n", (int)size, buffer);
    sample->operation_count++;
}

static void on_error(void* context, IO_ERROR_RESULT error_result)
{
    (void)context;
    (void)error_result;
    printf("Error detected\n");
}

static void on_accept_conn(void* context, const void* config)
{
    const SOCKETIO_CONFIG* socket_config = (const SOCKETIO_CONFIG*)config;

    printf("Accepted connection from hostname: %s\n", socket_config->hostname);
    SAMPLE_DATA* sample = (SAMPLE_DATA*)context;
    PATCHCORD_CALLBACK_INFO client_info;
    client_info.on_bytes_received = on_bytes_recv;
    client_info.on_bytes_received_ctx = sample;
    client_info.on_io_error = on_error;
    client_info.on_io_error_ctx = sample;
    sample->operation_count = 0;
    sample->incoming_socket = patchcord_client_create(cord_socket_get_interface(), config, &client_info);
}

int main()
{
    SAMPLE_DATA data = {0};
    SOCKETIO_CONFIG config = {0};
    config.hostname = "127.0.0.1";
    config.port = 4848;
    config.address_type = ADDRESS_TYPE_IP;

    const IO_INTERFACE_DESCRIPTION* io_desc = cord_socket_get_interface();
    PATCHCORD_CALLBACK_INFO client_info;
    client_info.on_bytes_received = on_bytes_recv;
    client_info.on_bytes_received_ctx = &data;
    client_info.on_io_error = on_error;
    client_info.on_io_error_ctx = &data;

    PATCH_INSTANCE_HANDLE xio_handle = patchcord_client_create(io_desc, &config, &client_info);
    if (xio_handle == NULL)
    {
        printf("Failure creating socket\n");
    }
    else
    {
        printf("Listening for connection on port %d\n", (int)config.port);
        if (patchcord_client_listen(xio_handle, on_accept_conn, &data) != 0)
        {
            printf("Failed listening to socket\n");
        }
        else
        {
            do
            {
                patchcord_client_process_item(xio_handle);
                if (data.incoming_socket != NULL)
                {
                    patchcord_client_process_item(data.incoming_socket);
                }
                if (data.operation_count == 1)
                {
                    patchcord_client_close(data.incoming_socket, on_close_complete, &data);
                }
                else if (data.operation_count == 2)
                {
                    patchcord_client_destroy(data.incoming_socket);
                    data.incoming_socket = NULL;
                }
            } while (data.keep_running == 0);
        }
        patchcord_client_destroy(xio_handle);
    }
    return 0;
}