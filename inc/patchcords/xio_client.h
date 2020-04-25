// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef XIO_CLIENT_H
#define XIO_CLIENT_H

#include "umock_c/umock_c_prod.h"
#include "azure_macro_utils/macro_utils.h"

#ifdef __cplusplus
#include <cstddef>
#include <cstdint>
extern "C" {
#else
#include <stddef.h>
#include <stdint.h>
#endif /* __cplusplus */

typedef struct XIO_INSTANCE_TAG* XIO_INSTANCE_HANDLE;
typedef void* XIO_IMPL_HANDLE;

typedef enum IO_SEND_RESULT_TAG
{
    IO_SEND_OK,
    IO_SEND_ERROR,
    IO_SEND_CANCELLED
} IO_SEND_RESULT;

typedef enum IO_OPEN_RESULT_TAG
{
    IO_OPEN_OK,
    IO_OPEN_ERROR,
    IO_OPEN_CANCELLED
} IO_OPEN_RESULT;

typedef enum IO_ERROR_RESULT_TAG
{
    IO_ERROR_OK,
    IO_ERROR_GENERAL,
    IO_ERROR_MEMORY,
    IO_ERROR_SERVER_DISCONN
} IO_ERROR_RESULT;

typedef enum SOCKETIO_ADDRESS_TYPE_TAG
{
    ADDRESS_TYPE_IP,
    ADDRESS_TYPE_DOMAIN_SOCKET,
    ADDRESS_TYPE_UDP
} SOCKETIO_ADDRESS_TYPE;

typedef struct ACCEPT_SOCKET_TAG
{
    const char* ip_address;
    uint16_t port;
} ACCEPT_SOCKET;

typedef struct SOCKETIO_CONFIG_TAG
{
    const char* hostname;
    uint16_t port;
    SOCKETIO_ADDRESS_TYPE address_type;
    void* accepted_socket;
} SOCKETIO_CONFIG;

typedef void(*ON_BYTES_RECEIVED)(void* context, const unsigned char* buffer, size_t size);
typedef void(*ON_SEND_COMPLETE)(void* context, IO_SEND_RESULT send_result);
typedef void(*ON_IO_OPEN_COMPLETE)(void* context, IO_OPEN_RESULT open_result);
typedef void(*ON_IO_CLOSE_COMPLETE)(void* context);
typedef void(*ON_IO_ERROR)(void* context, IO_ERROR_RESULT error_result);

typedef void(*ON_INCOMING_CONNECT)(void* context, const SOCKETIO_CONFIG* config);

typedef XIO_IMPL_HANDLE(*IO_CREATE)(const void* io_create_parameters);
typedef void(*IO_DESTROY)(XIO_IMPL_HANDLE impl_handle);
typedef int(*IO_OPEN)(XIO_IMPL_HANDLE impl_handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_ctx, ON_IO_ERROR on_io_error, void* on_io_error_ctx);
typedef int(*IO_CLOSE)(XIO_IMPL_HANDLE impl_handle, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context);
typedef int(*IO_SEND)(XIO_IMPL_HANDLE impl_handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_ctx);
typedef void(*IO_PROCESS_ITEM)(XIO_IMPL_HANDLE impl_handle);
typedef const char*(*IO_QUERY_URI)(XIO_IMPL_HANDLE impl_handle);
typedef uint16_t(*IO_QUERY_PORT)(XIO_IMPL_HANDLE impl_handle);
typedef int(*IO_LISTEN)(XIO_IMPL_HANDLE impl_handle, ON_INCOMING_CONNECT incoming_conn, void* user_ctx);

typedef struct IO_INTERFACE_DESCRIPTION_TAG
{
    IO_CREATE interface_impl_create;
    IO_DESTROY interface_impl_destroy;
    IO_OPEN interface_impl_open;
    IO_CLOSE interface_impl_close;
    IO_SEND interface_impl_send;
    IO_PROCESS_ITEM interface_impl_process_item;
    IO_QUERY_URI interface_impl_query_uri;
    IO_QUERY_PORT interface_impl_query_port;
    IO_LISTEN interface_impl_listen;
} IO_INTERFACE_DESCRIPTION;

typedef struct XIO_CLIENT_CALLBACK_INFO_TAG
{
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    void* on_io_open_complete_ctx;
    ON_BYTES_RECEIVED on_bytes_received;
    void* on_bytes_received_ctx;
    ON_IO_ERROR on_io_error;
    void* on_io_error_ctx;
} XIO_CLIENT_CALLBACK_INFO;

MOCKABLE_FUNCTION(, XIO_INSTANCE_HANDLE, xio_client_create, const IO_INTERFACE_DESCRIPTION*, io_interface_description, const void*, parameters);
MOCKABLE_FUNCTION(, void, xio_client_destroy, XIO_INSTANCE_HANDLE, xio);
MOCKABLE_FUNCTION(, int, xio_client_open, XIO_INSTANCE_HANDLE, xio, const XIO_CLIENT_CALLBACK_INFO*, client_callbacks);
MOCKABLE_FUNCTION(, int, xio_client_listen, XIO_INSTANCE_HANDLE, xio, ON_INCOMING_CONNECT, incoming_conn, void*, user_ctx);
MOCKABLE_FUNCTION(, int, xio_client_close, XIO_INSTANCE_HANDLE, xio, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, xio_client_send, XIO_INSTANCE_HANDLE, xio, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, xio_client_process_item, XIO_INSTANCE_HANDLE, xio);

MOCKABLE_FUNCTION(, const char*, xio_client_query_endpoint, XIO_INSTANCE_HANDLE, xio, uint16_t*, port);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // XIO_CLIENT_H
