// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifndef XIO_CLIENT_H
#define XIO_CLIENT_H

#include "umock_c/umock_c_prod.h"
#include "azure_macro_utils/macro_utils.h"

#ifdef __cplusplus
#include <cstddef>
extern "C" {
#else
#include <stddef.h>
#endif /* __cplusplus */

typedef struct XIO_INSTANCE_TAG* XIO_INSTANCE_HANDLE;
typedef void* XIO_IMPL_HANDLE;

#define IO_SEND_RESULT_VALUES   \
    IO_SEND_OK,                 \
    IO_SEND_ERROR,              \
    IO_SEND_CANCELLED

MU_DEFINE_ENUM(IO_SEND_RESULT, IO_SEND_RESULT_VALUES);

#define IO_OPEN_RESULT_VALUES   \
    IO_OPEN_OK,                 \
    IO_OPEN_ERROR,              \
    IO_OPEN_CANCELLED

MU_DEFINE_ENUM(IO_OPEN_RESULT, IO_OPEN_RESULT_VALUES);

#define IO_ERROR_RESULT_VALUES  \
    IO_ERROR_OK,                \
    IO_ERROR_GENERAL,           \
    IO_ERROR_MEMORY,            \
    IO_ERROR_SERVER_DISCONN

MU_DEFINE_ENUM(IO_ERROR_RESULT, IO_ERROR_RESULT_VALUES);

typedef void(*ON_BYTES_RECEIVED)(void* context, const unsigned char* buffer, size_t size);
typedef void(*ON_SEND_COMPLETE)(void* context, IO_SEND_RESULT send_result);
typedef void(*ON_IO_OPEN_COMPLETE)(void* context, IO_OPEN_RESULT open_result);
typedef void(*ON_IO_CLOSE_COMPLETE)(void* context);
typedef void(*ON_IO_ERROR)(void* context, IO_ERROR_RESULT error_result);

typedef XIO_IMPL_HANDLE(*IO_CREATE)(const void* io_create_parameters);
typedef void(*IO_DESTROY)(XIO_IMPL_HANDLE impl_handle);
typedef int(*IO_OPEN)(XIO_IMPL_HANDLE impl_handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_ctx, ON_IO_ERROR on_io_error, void* on_io_error_ctx);
typedef int(*IO_CLOSE)(XIO_IMPL_HANDLE impl_handle, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context);
typedef int(*IO_SEND)(XIO_IMPL_HANDLE impl_handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_ctx);
typedef void(*IO_PROCESS_ITEM)(XIO_IMPL_HANDLE impl_handle);
typedef const char*(*IO_QUERY_ENDPOINT)(XIO_IMPL_HANDLE impl_handle);

typedef struct IO_INTERFACE_DESCRIPTION_TAG
{
    IO_CREATE interface_impl_create;
    IO_DESTROY interface_impl_destroy;
    IO_OPEN interface_impl_open;
    IO_CLOSE interface_impl_close;
    IO_SEND interface_impl_send;
    IO_PROCESS_ITEM interface_impl_process_item;
    IO_QUERY_ENDPOINT interface_impl_query_endpoint;
} IO_INTERFACE_DESCRIPTION;

MOCKABLE_FUNCTION(, XIO_INSTANCE_HANDLE, xio_client_create, const IO_INTERFACE_DESCRIPTION*, io_interface_description, const void*, parameters);
MOCKABLE_FUNCTION(, void, xio_client_destroy, XIO_INSTANCE_HANDLE, xio);
MOCKABLE_FUNCTION(, int, xio_client_open, XIO_INSTANCE_HANDLE, xio, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context, ON_BYTES_RECEIVED, on_bytes_received, void*, on_bytes_received_context, ON_IO_ERROR, on_io_error, void*, on_io_error_context);
MOCKABLE_FUNCTION(, int, xio_client_close, XIO_INSTANCE_HANDLE, xio, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, xio_client_send, XIO_INSTANCE_HANDLE, xio, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, xio_client_process_item, XIO_INSTANCE_HANDLE, xio);

MOCKABLE_FUNCTION(, const char*, xio_client_query_endpoint, XIO_INSTANCE_HANDLE, xio);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif // XIO_CLIENT_H
