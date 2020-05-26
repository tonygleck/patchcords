// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "umock_c/umock_c_prod.h"
#include "azure_macro_utils/macro_utils.h"
#include "patchcords/cord_client.h"

#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
extern "C" {
#else
#include <stdint.h>
#include <stddef.h>
#endif /* __cplusplus */

MOCKABLE_FUNCTION(, CORD_HANDLE, cord_client_create, const void*, parameters, ON_BYTES_RECEIVED, on_bytes_received, void*, on_bytes_received_context, ON_IO_ERROR, on_io_error, void*, on_io_error_context);
MOCKABLE_FUNCTION(, void, cord_client_destroy, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, int, cord_client_open, CORD_HANDLE, xio, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context);
MOCKABLE_FUNCTION(, int, cord_client_listen, CORD_HANDLE, xio, ON_INCOMING_CONNECT, incoming_conn_cb, void*, user_ctx);
MOCKABLE_FUNCTION(, int, cord_client_close, CORD_HANDLE, xio, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, cord_client_send, CORD_HANDLE, xio, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, cord_client_process_item, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, int, cord_client_set_client_cert, CORD_HANDLE, handle, const char*, certificate, const unsigned char*, private_key);
MOCKABLE_FUNCTION(, int, cord_client_set_server_cert, CORD_HANDLE, handle, const char*, certificate);
MOCKABLE_FUNCTION(, const char*, cord_client_query_uri, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, uint16_t, cord_client_query_port, CORD_HANDLE, xio);

MOCKABLE_FUNCTION(, const IO_INTERFACE_DESCRIPTION*, xio_cord_get_interface);

#ifdef __cplusplus
}
#endif /* __cplusplus */
