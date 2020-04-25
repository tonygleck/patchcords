// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stddef.h>

#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/app_logging.h"
#include "patchcords/xio_client.h"

typedef struct XIO_INSTANCE_TAG
{
    const IO_INTERFACE_DESCRIPTION* io_interface_description;
    XIO_IMPL_HANDLE concrete_xio_handle;
} XIO_INSTANCE;

XIO_INSTANCE_HANDLE xio_client_create(const IO_INTERFACE_DESCRIPTION* io_interface_description, const void* parameters)
{
    XIO_INSTANCE* result;
    if ((io_interface_description == NULL) ||
        (io_interface_description->interface_impl_create == NULL) ||
        (io_interface_description->interface_impl_destroy == NULL) ||
        (io_interface_description->interface_impl_open == NULL) ||
        (io_interface_description->interface_impl_close == NULL) ||
        (io_interface_description->interface_impl_send == NULL) ||
        (io_interface_description->interface_impl_process_item == NULL) ||
        (io_interface_description->interface_impl_query_uri == NULL) ||
        (io_interface_description->interface_impl_query_port == NULL) )
    {
        log_error("Invalid interface description specified");
        result = NULL;
    }
    else
    {
        /* Codes_SRS_XIO_01_017: [If allocating the memory needed for the IO interface fails then xio_create shall return NULL.] */
        if ((result = (XIO_INSTANCE*)malloc(sizeof(XIO_INSTANCE))) != NULL)
        {
            result->io_interface_description = io_interface_description;
            if ((result->concrete_xio_handle  = result->io_interface_description->interface_impl_create(parameters)) == NULL)
            {
                log_error("Failure calling interface create");
                free(result);
                result = NULL;
            }
        }
        else
        {
            log_error("Failure allocating io instance");
        }
    }
    return (XIO_INSTANCE_HANDLE)result;
}

void xio_client_destroy(XIO_INSTANCE_HANDLE xio)
{
    if (xio != NULL)
    {
        XIO_INSTANCE* xio_instance = (XIO_INSTANCE*)xio;
        xio_instance->io_interface_description->interface_impl_destroy(xio_instance->concrete_xio_handle);
        free(xio_instance);
    }
}

int xio_client_open(XIO_INSTANCE_HANDLE xio, const XIO_CLIENT_CALLBACK_INFO* client_cbs)
{
    int result;
    if (xio == NULL || client_cbs == NULL)
    {
        log_error("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        XIO_INSTANCE* xio_instance = (XIO_INSTANCE*)xio;
        result = xio_instance->io_interface_description->interface_impl_open(xio_instance->concrete_xio_handle, client_cbs->on_io_open_complete,
            client_cbs->on_io_open_complete_ctx, client_cbs->on_bytes_received, client_cbs->on_bytes_received_ctx, client_cbs->on_io_error,
            client_cbs->on_io_error_ctx);
    }
    return result;
}

int xio_client_listen(XIO_INSTANCE_HANDLE xio, ON_INCOMING_CONNECT incoming_conn, void* user_ctx)
{
    int result;
    if (xio == NULL)
    {
        log_error("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        XIO_INSTANCE* xio_instance = (XIO_INSTANCE*)xio;
        if (xio_instance->io_interface_description->interface_impl_listen == NULL)
        {
            log_error("Failure listening function not implemented");
            result = __LINE__;
        }
        else
        {
            result = xio_instance->io_interface_description->interface_impl_listen(xio_instance->concrete_xio_handle, incoming_conn, user_ctx);
        }
    }
    return result;
}

int xio_client_close(XIO_INSTANCE_HANDLE xio, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
{
    int result;
    if (xio == NULL)
    {
        log_error("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        XIO_INSTANCE* xio_instance = (XIO_INSTANCE*)xio;
        result = xio_instance->io_interface_description->interface_impl_close(xio_instance->concrete_xio_handle, on_io_close_complete, callback_context);
    }
    return result;
}

int xio_client_send(XIO_INSTANCE_HANDLE xio, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    if (xio == NULL)
    {
        log_error("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        XIO_INSTANCE* xio_instance = (XIO_INSTANCE*)xio;
        result = xio_instance->io_interface_description->interface_impl_send(xio_instance->concrete_xio_handle, buffer, size, on_send_complete, callback_context);
    }
    return result;
}

void xio_client_process_item(XIO_INSTANCE_HANDLE xio)
{
    if (xio != NULL)
    {
        XIO_INSTANCE* xio_instance = (XIO_INSTANCE*)xio;
        xio_instance->io_interface_description->interface_impl_process_item(xio_instance->concrete_xio_handle);
    }
}

const char* xio_client_query_endpoint(XIO_INSTANCE_HANDLE xio, uint16_t* port)
{
    const char* result;
    if (xio == NULL)
    {
        log_error("Invalid parameter specified");
        result = NULL;
    }
    else
    {
        XIO_INSTANCE* xio_instance = (XIO_INSTANCE*)xio;

        if (port != NULL)
        {
            *port = xio_instance->io_interface_description->interface_impl_query_port(xio_instance->concrete_xio_handle);
        }
        result = xio_instance->io_interface_description->interface_impl_query_uri(xio_instance->concrete_xio_handle);
    }
    return result;
}
