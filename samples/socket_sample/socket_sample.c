// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "patchcords/xio_client.h"
#include "patchcords/xio_socket.h"

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

void on_xio_bytes_recv(void* context, const unsigned char* buffer, size_t size)
{

}

void on_xio_error(void* context, IO_ERROR_RESULT error_result)
{
    printf("Error detected\n");
}

int main()
{
    SOCKETIO_CONFIG config = {0};
    config.hostname = "127.0.0.1";
    config.port = 4444;
    config.address_type = ADDRESS_TYPE_IP;

    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    if (handle == NULL)
    {
        printf("Failure creating socket");
    }
    else
    {
        SAMPLE_DATA data;
        if (xio_socket_open(handle, on_xio_open_complete, &data, on_xio_bytes_recv, &data, on_xio_error, NULL) != 0)
        {
            printf("Failed socket open");
        }

        do
        {
            xio_socket_dowork(handle);

            if (data.socket_open > 0)
            {
                if (data.send_complete == 0)
                {
                    // Send socket
                    if (xio_socket_send(handle, TEST_SEND_DATA, strlen(TEST_SEND_DATA), on_xio_send_complete, &data) != 0)
                    {
                        printf("Failure sending data to socket\n");
                    }
                }
                else if (data.send_complete >= 2)
                {
                    xio_socket_close(handle, on_xio_close_complete, &data);
                }
            }
            if (data.socket_closed > 0)
            {
                break;
            }
        } while (data.keep_running == 0);

        xio_socket_destroy(handle);
    }

    return 0;
}