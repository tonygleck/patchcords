// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "umock_c/umock_c_prod.h"
#include "azure_macro_utils/macro_utils.h"
#include "patchcords/patchcord_client.h"

#ifdef __cplusplus
extern "C" {
#else
#endif /* __cplusplus */

typedef struct SOCKETIO_CONFIG_TAG
{
    const char* hostname;
    uint16_t port;
    SOCKETIO_ADDRESS_TYPE address_type;
    void* accepted_socket;
} SOCKETIO_CONFIG;

MOCKABLE_FUNCTION(, CORD_HANDLE, cord_socket_create, const void*, parameters, const PATCHCORD_CALLBACK_INFO*, client_cb);
MOCKABLE_FUNCTION(, void, cord_socket_destroy, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, int, cord_socket_open, CORD_HANDLE, xio, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context);
MOCKABLE_FUNCTION(, int, cord_socket_listen, CORD_HANDLE, xio, ON_INCOMING_CONNECT, incoming_conn_cb, void*, user_ctx);
MOCKABLE_FUNCTION(, int, cord_socket_close, CORD_HANDLE, xio, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, cord_socket_send, CORD_HANDLE, xio, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, cord_socket_process_item, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, const char*, cord_socket_query_uri, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, uint16_t, cord_socket_query_port, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, const IO_INTERFACE_DESCRIPTION*, cord_socket_get_interface);

#ifdef __cplusplus
}
#endif /* __cplusplus */
