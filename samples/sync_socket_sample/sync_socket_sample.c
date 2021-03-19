// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "patchcords/patchcord_client.h"
#include "patchcords/cord_tls_client.h"
#include "patchcords/cord_socket_client.h"


typedef struct SAMPLE_DATA_TAG
{
    int keep_running;
    int socket_open;
    int socket_closed;
    int send_complete;
} SAMPLE_DATA;

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

void on_xio_bytes_recv(void* context, const unsigned char* buffer, size_t size, const void* config)
{

}

void on_xio_error(void* context, IO_ERROR_RESULT error_result)
{
    printf("Error detected\n");
}

int main()
{
    SAMPLE_DATA data = {0};
    SOCKETIO_CONFIG config = {0};
    config.hostname = "127.0.0.1";
    config.port = 4444;
    config.address_type = ADDRESS_TYPE_IP;

    PATCHCORD_CALLBACK_INFO client_info;
    client_info.on_bytes_received = on_xio_bytes_recv;
    client_info.on_bytes_received_ctx = &data;
    client_info.on_io_error = on_xio_error;
    client_info.on_io_error_ctx = &data;

    CORD_HANDLE handle = patchcord_client_create(cord_socket_get_interface(), &config, &client_info);
    if (handle == NULL)
    {
        printf("Failure creating socket");
    }
    else
    {
        (void)patchcord_client_enable_async(handle, false);
        if (patchcord_client_open(handle, NULL, NULL) != 0)
        {
            printf("Failed socket open");
        }
        else
        {
            // Send socket
            if (patchcord_client_send(handle, TEST_SEND_DATA, strlen(TEST_SEND_DATA), NULL, NULL) != 0)
            {
                printf("Failure sending data to socket\n");
            }
            else
            {
                printf("Successfully sent message\n");
            }
            patchcord_client_close(handle, NULL, NULL);

            patchcord_client_destroy(handle);
        }
    }
    return 0;
}