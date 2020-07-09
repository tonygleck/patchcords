// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef patchcord_client_H
#define patchcord_client_H

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

typedef struct PATCH_INSTANCE_TAG* PATCH_INSTANCE_HANDLE;
typedef void* CORD_HANDLE;

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
    IO_ERROR_ENDPOINT_DISCONN
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

typedef void(*ON_BYTES_RECEIVED)(void* context, const unsigned char* buffer, size_t size);
typedef void(*ON_SEND_COMPLETE)(void* context, IO_SEND_RESULT send_result);
typedef void(*ON_IO_OPEN_COMPLETE)(void* context, IO_OPEN_RESULT open_result);
typedef void(*ON_IO_CLOSE_COMPLETE)(void* context);
typedef void(*ON_IO_ERROR)(void* context, IO_ERROR_RESULT error_result);
typedef void(*ON_CLIENT_CLOSED)(void* context);

typedef void(*ON_INCOMING_CONNECT)(void* context, const void* config);

typedef struct PATCHCORD_CALLBACK_INFO_TAG
{
    ON_BYTES_RECEIVED on_bytes_received;
    void* on_bytes_received_ctx;
    ON_IO_ERROR on_io_error;
    void* on_io_error_ctx;
    ON_CLIENT_CLOSED on_client_close;
    void* on_close_ctx;
} PATCHCORD_CALLBACK_INFO;

typedef CORD_HANDLE(*IO_CREATE)(const void* io_create_parameters, const PATCHCORD_CALLBACK_INFO* client_cb);
typedef void(*IO_DESTROY)(CORD_HANDLE impl_handle);
typedef int(*IO_OPEN)(CORD_HANDLE impl_handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_ctx);
typedef int(*IO_CLOSE)(CORD_HANDLE impl_handle, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context);
typedef int(*IO_SEND)(CORD_HANDLE impl_handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_ctx);
typedef void(*IO_PROCESS_ITEM)(CORD_HANDLE impl_handle);
typedef const char*(*IO_QUERY_URI)(CORD_HANDLE impl_handle);
typedef uint16_t(*IO_QUERY_PORT)(CORD_HANDLE impl_handle);
typedef int(*IO_LISTEN)(CORD_HANDLE impl_handle, ON_INCOMING_CONNECT incoming_conn, void* user_ctx);

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

MOCKABLE_FUNCTION(, PATCH_INSTANCE_HANDLE, patchcord_client_create, const IO_INTERFACE_DESCRIPTION*, io_interface_description, const void*, parameters, const PATCHCORD_CALLBACK_INFO*, client_cb);
MOCKABLE_FUNCTION(, void, patchcord_client_destroy, PATCH_INSTANCE_HANDLE, xio);
MOCKABLE_FUNCTION(, int, patchcord_client_open, PATCH_INSTANCE_HANDLE, xio, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_ctx);
MOCKABLE_FUNCTION(, int, patchcord_client_listen, PATCH_INSTANCE_HANDLE, xio, ON_INCOMING_CONNECT, incoming_conn, void*, user_ctx);
MOCKABLE_FUNCTION(, int, patchcord_client_close, PATCH_INSTANCE_HANDLE, xio, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, patchcord_client_send, PATCH_INSTANCE_HANDLE, xio, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, patchcord_client_process_item, PATCH_INSTANCE_HANDLE, xio);

MOCKABLE_FUNCTION(, const char*, patchcord_client_query_endpoint, PATCH_INSTANCE_HANDLE, xio, uint16_t*, port);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // patchcord_client_H
