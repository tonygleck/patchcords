// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#pragma once

#include "umock_c/umock_c_prod.h"
#include "azure_macro_utils/macro_utils.h"
#include "patchcords/patchcord_client.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct TLS_CONFIG_TAG
{
    const char* hostname;
    uint16_t port;
    const void* socket_config;
    const IO_INTERFACE_DESCRIPTION* socket_desc;
    const char* server_certifiate;
    const char* client_certificate;
    const void* pkey_certificate;
} TLS_CONFIG;

MOCKABLE_FUNCTION(, CORD_HANDLE, cord_tls_create, const void*, parameters, const PATCHCORD_CALLBACK_INFO*, client_cb);
MOCKABLE_FUNCTION(, void, cord_tls_destroy, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, int, cord_tls_open, CORD_HANDLE, xio, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_ctx);
MOCKABLE_FUNCTION(, int, cord_tls_listen, CORD_HANDLE, xio, ON_INCOMING_CONNECT, incoming_conn_cb, void*, user_ctx);
MOCKABLE_FUNCTION(, int, cord_tls_close, CORD_HANDLE, xio, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, cord_tls_send, CORD_HANDLE, xio, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, cord_tls_process_item, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, const char*, cord_tls_query_uri, CORD_HANDLE, xio);
MOCKABLE_FUNCTION(, uint16_t, cord_tls_query_port, CORD_HANDLE, xio);

MOCKABLE_FUNCTION(, const IO_INTERFACE_DESCRIPTION*, cord_tls_get_tls_interface);

#ifdef __cplusplus
}
#endif /* __cplusplus */
