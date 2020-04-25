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

void on_accept_conn(void* context, const SOCKETIO_CONFIG* config)
{

}

int main()
{
    SOCKETIO_CONFIG config = {0};
    config.hostname = "127.0.0.1";
    config.port = 4444;
    config.address_type = ADDRESS_TYPE_IP;

    const IO_INTERFACE_DESCRIPTION* io_desc = xio_socket_get_interface();

    XIO_INSTANCE_HANDLE xio_handle = xio_client_create(io_desc, &config);
    if (xio_handle == NULL)
    {
        printf("Failure creating socket");
    }
    else
    {
        SAMPLE_DATA data = {0};
        if (xio_client_listen(xio_handle, on_accept_conn, &data) != 0)
        {
            printf("Failed socket open");
        }
        else
        {
            do
            {
                xio_client_process_item(xio_handle);

                if (data.socket_open > 0)
                {
                }
                if (data.socket_closed > 0)
                {
                    break;
                }
            } while (data.keep_running == 0);
        }
        xio_client_destroy(xio_handle);
    }
    return 0;
}