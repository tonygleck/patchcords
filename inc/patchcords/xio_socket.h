// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef XIO_SOCKET_H
#define XIO_SOCKET_H

#include "umock_c/umock_c_prod.h"
#include "azure_macro_utils/macro_utils.h"
#include "patchcords/xio_socket.h"

#ifdef __cplusplus
#include <cstdint>
#include <cstddef>
extern "C" {
#else
#include <stdint.h>
#include <stddef.h>
#endif /* __cplusplus */

MOCKABLE_FUNCTION(, XIO_IMPL_HANDLE, xio_socket_create, const void*, parameters, ON_BYTES_RECEIVED, on_bytes_received, void*, on_bytes_received_context, ON_IO_ERROR, on_io_error, void*, on_io_error_context);
MOCKABLE_FUNCTION(, void, xio_socket_destroy, XIO_IMPL_HANDLE, xio);
MOCKABLE_FUNCTION(, int, xio_socket_open, XIO_IMPL_HANDLE, xio, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context);
MOCKABLE_FUNCTION(, int, xio_socket_listen, XIO_IMPL_HANDLE, xio, ON_INCOMING_CONNECT, incoming_conn_cb, void*, user_ctx);
MOCKABLE_FUNCTION(, int, xio_socket_close, XIO_IMPL_HANDLE, xio, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, xio_socket_send, XIO_IMPL_HANDLE, xio, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, xio_socket_process_item, XIO_IMPL_HANDLE, xio);
MOCKABLE_FUNCTION(, const IO_INTERFACE_DESCRIPTION*, xio_socket_get_interface);

MOCKABLE_FUNCTION(, const char*, xio_socket_query_uri, XIO_IMPL_HANDLE, xio);
MOCKABLE_FUNCTION(, uint16_t, xio_socket_query_port, XIO_IMPL_HANDLE, xio);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // XIO_CLIENT_H
