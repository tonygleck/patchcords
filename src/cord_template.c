// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/app_logging.h"
#include "patchcords/patchcord_client.h"
#include "patchcords/cord_client.h"

typedef enum SOCKET_STATE_TAG
{
    IO_STATE_CLOSED,
    IO_STATE_CLOSING,
    IO_STATE_OPENING,
    IO_STATE_OPEN,
    IO_STATE_ERROR
} SOCKET_STATE;

typedef struct SOCKET_INSTANCE_TAG
{
    int socket;
    char* hostname;
    uint16_t port;
    SOCKETIO_ADDRESS_TYPE address_type;
    SOCKET_STATE current_state;

    ON_IO_OPEN_COMPLETE on_io_open_complete;
    void* on_io_open_complete_context;
    ON_BYTES_RECEIVED on_bytes_received;
    void* on_bytes_received_context;
    ON_IO_ERROR on_io_error;
    void* on_io_error_context;
} SOCKET_INSTANCE;

static int clone_string(char** target, const char* source)
{
    int result;
    if (target == NULL || source == NULL)
    {
        result = __LINE__;
    }
    else
    {
        size_t length = strlen(source);
        if ((*target = malloc(length+1)) == NULL)
        {
            result = __LINE__;
        }
        else
        {
            memset(*target, 0, length+1);
            memcpy(*target, source, length);
            result = 0;
        }
    }
    return result;
}

int open_socket(SOCKET_INSTANCE* socket_impl)
{

}

CORD_HANDLE cord_client_create(const void* parameters)
{
    SOCKET_INSTANCE* result;
    if (parameters == NULL)
    {
        log_error("Invalid parameter specified");
        result = NULL;
    }
    else if ((result = malloc(sizeof(SOCKET_INSTANCE))) == NULL)
    {
        log_error("Failure allocating socket instance");
    }
    else
    {
        const SOCKETIO_CONFIG* config = (const SOCKETIO_CONFIG*)parameters;
        memset(result, 0, sizeof(SOCKET_INSTANCE));
        result->port = config->port;
        result->address_type = config->address_type;

        // Copy the host name
        if (clone_string(&result->hostname, config->hostname) != 0)
        {
            log_error("Failure cloning hostname value");
            free(result);
            result = NULL;
        }
    }
    return (CORD_HANDLE)result;
}

void cord_client_destroy(CORD_HANDLE xio)
{
    if (xio != NULL)
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
        free(socket_impl->hostname);
        free(socket_impl);
    }
}

int cord_client_open(CORD_HANDLE xio, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    int result;
    if (xio == NULL)
    {
        log_error("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
        if (socket_impl->current_state == IO_STATE_OPENING || socket_impl->current_state == IO_STATE_OPEN)
        {
            log_error("Socket is in invalid state to open");
            result = __LINE__;
        }
        else
        {
            socket_impl->current_state = IO_STATE_OPENING;
            socket_impl->on_io_open_complete = on_io_open_complete;
            socket_impl->on_io_open_complete_context = on_io_open_complete_context;
            socket_impl->on_bytes_received = on_bytes_received;
            socket_impl->on_bytes_received_context = on_bytes_received_context;
            socket_impl->on_io_error = on_io_error;
            socket_impl->on_io_error_context = on_io_error_context;
            result = 0;
        }
    }
    return result;
}

int cord_client_close(CORD_HANDLE xio, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result;
    if (xio == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
            result = 0;
    }
    return result;
}

int cord_client_send(CORD_HANDLE xio, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    if (xio == NULL)
    {
        result = MU_FAILURE;
    }
    else
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
    }
    return result;
}

void cord_client_dowork(CORD_HANDLE xio)
{
    if (xio != NULL)
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;

        if (socket_impl->current_state == IO_STATE_OPENING)
        {
            // Open the socket
        }
        else if (socket_impl->current_state == IO_STATE_CLOSING)
        {

        }
        else if (socket_impl->current_state == IO_STATE_OPEN)
        {
            /* code */
        }
        else
        {

        }
    }
}

static const IO_INTERFACE_DESCRIPTION socket_io_interface =
{
    cord_client_create,
    cord_client_destroy,
    cord_client_open,
    cord_client_close,
    cord_client_send,
    cord_client_dowork,
};

const IO_INTERFACE_DESCRIPTION* xio_cord_get_interface(void)
{
    return &socket_io_interface;
}