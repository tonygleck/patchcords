// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#define SECURITY_WIN32

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include <windows.h>
#include <sspi.h>
#include <schannel.h>

#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/app_logging.h"
#include "lib-util-c/crt_extensions.h"

#include "patchcords/patchcord_client.h"
#include "patchcords/cord_tls_client.h"
#include "patchcords/cord_socket_client.h"

typedef enum SOCKET_STATE_TAG
{
    IO_STATE_IDLE,
    IO_STATE_CLOSED,
    IO_STATE_CLOSING,
    IO_STATE_OPENING,
    IO_STATE_OPEN_ERROR,
    IO_STATE_OPEN,
    IO_STATE_HANDSHAKE,
    IO_STATE_HANDSHAKE_HELLO_SENT,
    IO_STATE_OPENED,
    IO_STATE_LISTENING,
    IO_STATE_ERROR,
    IO_STATE_STALE
} SOCKET_STATE;

typedef struct TLS_INSTANCE_TAG
{
    char* hostname;
    uint16_t port;
    SOCKETIO_ADDRESS_TYPE address_type;
    SOCKET_STATE current_state;

    ON_IO_OPEN_COMPLETE on_open_complete;
    void* on_open_complete_ctx;
    ON_BYTES_RECEIVED on_bytes_received;
    void* on_bytes_received_ctx;
    ON_IO_ERROR on_error;
    void* on_error_ctx;
    ON_IO_CLOSE_COMPLETE on_close_complete;
    void* on_close_complete_ctx;
    ON_CLIENT_CLOSED on_client_close;
    void* on_close_ctx;

    CORD_HANDLE underlying_socket;
    const IO_INTERFACE_DESCRIPTION* socket_iface;

    ON_INCOMING_CONNECT incoming_client_conn;
    void* client_conn_ctx;

    unsigned char* recv_buff;
    size_t recv_buff_size;

    // Schannel info
    //X509_SCHANNEL_HANDLE x509_schannel_handle;
    CredHandle cred_handle;
    CtxtHandle security_ctx;


    const char* server_cert;
    const char* certificate;
    const unsigned char* private_key;
} TLS_INSTANCE;

static int realloc_recv_block(TLS_INSTANCE* tls_instance, size_t bytes_needed)
{
    int result;
    if (bytes_needed > tls_instance->recv_buff_size)
    {
        unsigned char* buffer = (unsigned char*)realloc(tls_instance->recv_buff, bytes_needed);
        if (buffer == NULL)
        {
            log_error("Failure reallocating recv buffer");
            result = __LINE__;
        }
        else
        {
            tls_instance->recv_buff = buffer;
            tls_instance->recv_buff_size = bytes_needed;
            result = 0;
        }
    }
    else
    {
        result = 0;
    }
    return result;
}

static int send_tls_handshake(TLS_INSTANCE* tls_instance)
{
    int result;
    SCHANNEL_CRED cred_info = { 0 };
    cred_info.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;

    if (tls_instance->server_cert != NULL)
    {
        // Signals to schannel that it should use server_cert
        // and not look in the windows store
        cred_info.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    }

    SECURITY_STATUS status_res = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL,
        &cred_info, NULL, NULL, &tls_instance->cred_handle, NULL);
    if (status_res != SEC_E_OK)
    {
        log_error("Failure aquiring credential handle %d", status_res);
        result = __LINE__;
    }
    else
    {
        SecBuffer init_sec_buff[2];
        SecBufferDesc sec_buff;
        ULONG ctx_attrib;

        init_sec_buff[0].cbBuffer = 0;
        init_sec_buff[0].BufferType = SECBUFFER_TOKEN;
        init_sec_buff[0].pvBuffer = NULL;
        init_sec_buff[1].cbBuffer = 0;
        init_sec_buff[1].BufferType = SECBUFFER_EMPTY;
        init_sec_buff[1].pvBuffer = NULL;

        sec_buff.cBuffers = 2;
        sec_buff.pBuffers = init_sec_buff;
        sec_buff.ulVersion = SECBUFFER_VERSION;

        status_res = InitializeSecurityContext(&tls_instance->cred_handle, NULL, tls_instance->hostname, ISC_REQ_EXTENDED_ERROR | ISC_REQ_STREAM | ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_USE_SUPPLIED_CREDS,
            0, 0, NULL, 0, &tls_instance->security_ctx, &sec_buff, &ctx_attrib, NULL);
        if (status_res == SEC_I_COMPLETE_NEEDED || status_res == SEC_I_CONTINUE_NEEDED || status_res == SEC_I_COMPLETE_AND_CONTINUE)
        {
            // Send Data here
            if (tls_instance->socket_iface->interface_impl_send(tls_instance->underlying_socket, init_sec_buff[0].pvBuffer, init_sec_buff[0].cbBuffer, NULL, NULL) != 0)
            {
                log_error("Failure sending handshake data on socket");
                result = __LINE__;
            }
            else
            {
                tls_instance->recv_buff_size = 1;
                if (realloc_recv_block(tls_instance, tls_instance->recv_buff_size) != 0)
                {
                    log_error("Failure reallocating recv block");
                    result = __LINE__;
                }
                else
                {
                    tls_instance->current_state = IO_STATE_HANDSHAKE_HELLO_SENT;
                    result = 0;
                }
            }
        }
        else
        {
            result = 0;
        }
    }
    return result;
}

// Callbacks
static void on_socket_open_complete(void* ctx, IO_OPEN_RESULT open_result)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
        if (open_result == IO_OPEN_OK)
        {
            if (tls_instance->current_state == IO_STATE_OPENING)
            {
                tls_instance->current_state = IO_STATE_HANDSHAKE;
            }
        }
        else
        {
            tls_instance->current_state = IO_STATE_OPEN_ERROR;
            log_error("Failure opening socket");
        }
    }
    else
    {
        log_error("Failure on open complete ctx is NULL");
    }
}

static void on_socket_close_complete(void* ctx)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
        tls_instance->current_state = IO_STATE_CLOSED;
    }
}

static void on_socket_send_complete(void* ctx, IO_SEND_RESULT send_result)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
    }
}

static void on_socket_bytes_recv(void* ctx, const unsigned char* buffer, size_t size, const void* config)
{
    (void)config;
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
        if (realloc_recv_block(tls_instance, tls_instance->recv_buff_size + size) != 0)
        {
            tls_instance->current_state = IO_STATE_OPEN_ERROR;
            log_error("Failure reallocating recv block on recv");
        }
        else
        {

        }
    }
}

static void on_socket_error(void* ctx, IO_ERROR_RESULT error_result)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
        tls_instance->on_error(tls_instance->on_error_ctx, error_result);
    }
}

static void on_accept_conn(void* ctx, const void* config)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance == NULL)
    {
        const SOCKETIO_CONFIG* socket_config = (const SOCKETIO_CONFIG*)config;
    }
    else
    {
    }
}

static int create_underlying_socket(TLS_INSTANCE* tls_instance, const TLS_CONFIG* config)
{
    int result;
    PATCHCORD_CALLBACK_INFO client_cb = { on_socket_bytes_recv, tls_instance, on_socket_error, tls_instance, NULL, NULL };
    if ((tls_instance->socket_iface = config->socket_desc) == NULL ||
        tls_instance->socket_iface->interface_impl_create == NULL ||
        tls_instance->socket_iface->interface_impl_destroy == NULL ||
        tls_instance->socket_iface->interface_impl_open == NULL ||
        tls_instance->socket_iface->interface_impl_close == NULL ||
        tls_instance->socket_iface->interface_impl_process_item == NULL ||
        tls_instance->socket_iface->interface_impl_send == NULL ||
        tls_instance->socket_iface->interface_impl_listen == NULL ||
        tls_instance->socket_iface->interface_impl_query_uri == NULL ||
        tls_instance->socket_iface->interface_impl_query_port == NULL
    )
    {
        log_error("Socket Interface functions are invalid");
        result = __LINE__;
    }
    else if ((tls_instance->underlying_socket = tls_instance->socket_iface->interface_impl_create(config->socket_config, &client_cb)) == NULL)
    {
        log_error("Failure creating underlying socket");
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}

CORD_HANDLE cord_tls_create(const void* parameters, const PATCHCORD_CALLBACK_INFO* client_cb)
{
    TLS_INSTANCE* result;
    if (parameters == NULL)
    {
        log_error("Invalid parameter specified");
        result = NULL;
    }
    // Open the underlying socket
    else if ((result = malloc(sizeof(TLS_INSTANCE))) == NULL)
    {
        log_error("Failure allocating tls instance");
    }
    else
    {
        const TLS_CONFIG* config = (const TLS_CONFIG*)parameters;

        memset(result, 0, sizeof(TLS_INSTANCE));
        if (create_underlying_socket(result, config) != 0)
        {
            log_error("Failure cloning hostname value");
            free(result);
            result = NULL;
        }
        else if (clone_string(&result->hostname, config->hostname) != 0)
        {
            log_error("Failure cloning hostname value");
            result->socket_iface->interface_impl_destroy(result->underlying_socket);
            free(result);
            result = NULL;
        }
        else
        {
            result->on_bytes_received = client_cb->on_bytes_received;
            result->on_bytes_received_ctx = client_cb->on_bytes_received_ctx;
            result->on_error = client_cb->on_io_error;
            result->on_error_ctx = client_cb->on_io_error_ctx;
            result->on_client_close = client_cb->on_client_close;
            result->on_close_ctx = client_cb->on_close_ctx;
            result->port = config->port;

            result->certificate = config->client_certificate;
            result->private_key = config->pkey_certificate;
            result->server_cert = config->server_certifiate;
        }
    }
    return (CORD_HANDLE)result;
}

void cord_tls_destroy(CORD_HANDLE handle)
{
    if (handle != NULL)
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        tls_instance->socket_iface->interface_impl_destroy(tls_instance->underlying_socket);

        free(tls_instance->hostname);
        free(tls_instance);
    }
}

int cord_tls_open(CORD_HANDLE handle, ON_IO_OPEN_COMPLETE on_open_complete, void* on_open_complete_ctx)
{
    int result;
    if (handle == NULL)
    {
        log_error("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        if (tls_instance->current_state == IO_STATE_OPEN || tls_instance->current_state == IO_STATE_OPENING)
        {
            log_error("TLS Connection is in invalid state to open");
            result = __LINE__;
        }
        else
        {
            tls_instance->current_state = IO_STATE_OPEN;
            tls_instance->on_open_complete = on_open_complete;
            tls_instance->on_open_complete_ctx = on_open_complete_ctx;
            result = 0;
        }
    }
    return result;
}

int cord_tls_listen(CORD_HANDLE handle, ON_INCOMING_CONNECT incoming_conn_cb, void* user_ctx)
{
    uint16_t result;
    if (handle == NULL || incoming_conn_cb == NULL)
    {
        log_error("Failure invalid parameter specified handle: %p, incoming_conn_cb: %p", handle, incoming_conn_cb);
        result = __LINE__;
    }
    else
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        /*if (create_ssl_ctx(tls_instance) != 0)
        {
            log_error("Failure creating ssl context");
            result = __LINE__;
        }
        else if (load_certificates(tls_instance) != 0)
        {
            log_error("Failure loadding certificates");
            result = __LINE__;
        }
        else */
        tls_instance->incoming_client_conn = incoming_conn_cb;
        tls_instance->client_conn_ctx = user_ctx;

        if (tls_instance->socket_iface->interface_impl_listen(tls_instance->underlying_socket, on_accept_conn, tls_instance) != 0)
        {
            log_error("Failure Listening on socket");
            result = __LINE__;
        }
        else
        {
            tls_instance->current_state = IO_STATE_LISTENING;
            result = 0;
        }
    }
    return result;
}

int cord_tls_close(CORD_HANDLE handle, ON_IO_CLOSE_COMPLETE on_close_complete, void* callback_ctx)
{
    int result;
    if (handle == NULL)
    {
        log_error("Invalid parameter specified");
        result = MU_FAILURE;
    }
    else
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        if (tls_instance->current_state == IO_STATE_CLOSED || tls_instance->current_state == IO_STATE_CLOSING || tls_instance->current_state == IO_STATE_IDLE)
        {
            log_error("Failure can not close while already closing");
            result = __LINE__;
        }
        else
        {
            TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
            tls_instance->on_close_complete = on_close_complete;
            tls_instance->on_close_complete_ctx = callback_ctx;

            if (tls_instance->current_state == IO_STATE_OPENING || tls_instance->current_state == IO_STATE_OPEN)
            {
                tls_instance->on_open_complete(tls_instance->on_open_complete_ctx, IO_OPEN_CANCELLED);
            }

            if (tls_instance->socket_iface->interface_impl_close(tls_instance->underlying_socket, on_socket_close_complete, tls_instance) != 0)
            {
                log_warning("Failure attempting to close socket");
                tls_instance->current_state = IO_STATE_CLOSED;
            }
            else
            {
                tls_instance->current_state = IO_STATE_CLOSING;
            }
            result = 0;
        }
    }
    return result;
}

int cord_tls_send(CORD_HANDLE handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    if (handle == NULL || buffer == NULL)
    {
        log_error("Invalid parameter specified handle: %p, buffer %p", handle, buffer);
        result =__LINE__;
    }
    else
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        if (tls_instance->current_state != IO_STATE_OPENED)
        {
            log_error("Tls is in invalid state to open");
            result =__LINE__;
        }
        // else if (SSL_write(tls_instance->ssl_object, buffer, (int)size) != (int)size)
        // {
        //     log_error("Failure encrypting sending buffer");
        //     result =__LINE__;
        // }
        // else if (write_outgoing_bytes(tls_instance, on_send_complete, callback_context) != 0)
        // {
        //     log_error("Failure writing outgoig bytes");
        //     result =__LINE__;
        // }
        else
        {
            result = 0;
        }

    }
    return result;
}

void cord_tls_process_item(CORD_HANDLE handle)
{
    if (handle != NULL)
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        switch (tls_instance->current_state)
        {
            case IO_STATE_OPEN:
                // Open the socket
                if (tls_instance->socket_iface->interface_impl_open(tls_instance->underlying_socket, on_socket_open_complete, tls_instance) != 0)
                {
                    log_error("Failure opening underlying socket");
                    tls_instance->current_state = IO_STATE_ERROR;
                }
                else
                {
                    tls_instance->current_state = IO_STATE_OPENING;
                }
                break;
            case IO_STATE_HANDSHAKE:
                // state will change in the callback
                if (send_tls_handshake(tls_instance) != 0)
                {
                    log_error("Failure sending handshake");
                    tls_instance->current_state = IO_STATE_ERROR;
                }
                break;
            case IO_STATE_CLOSED:
                if (tls_instance->on_close_complete != NULL)
                {
                    tls_instance->on_close_complete(tls_instance->on_close_complete_ctx);
                }
                break;
            case IO_STATE_LISTENING:
            case IO_STATE_OPENING:
            case IO_STATE_CLOSING:
            case IO_STATE_OPENED:
            case IO_STATE_IDLE:
            case IO_STATE_STALE:
            case IO_STATE_HANDSHAKE_HELLO_SENT:
                break;
            case IO_STATE_OPEN_ERROR:
                if (tls_instance->on_open_complete != NULL)
                {
                    tls_instance->on_open_complete(tls_instance->on_open_complete_ctx, IO_OPEN_ERROR);
                }
                // Close from a partial open
                tls_instance->current_state = IO_STATE_IDLE;
                break;
            case IO_STATE_ERROR:
                if (tls_instance->on_error != NULL)
                {
                    tls_instance->on_error(tls_instance->on_error_ctx, IO_ERROR_GENERAL);
                }
                tls_instance->current_state = IO_STATE_STALE;
                break;
        }
        tls_instance->socket_iface->interface_impl_process_item(tls_instance->underlying_socket);
    }
}

const char* cord_tls_query_uri(CORD_HANDLE handle)
{
    const char* result;
    if (handle == NULL)
    {
        log_error("Failure invalid parameter specified handle: NULL");
        result = NULL;
    }
    else
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        result = tls_instance->hostname;
    }
    return result;
}

uint16_t cord_tls_query_port(CORD_HANDLE handle)
{
    uint16_t result;
    if (handle == NULL)
    {
        log_error("Failure invalid parameter specified handle: NULL");
        result = 0;
    }
    else
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        result = tls_instance->port;
    }
    return result;
}

static const IO_INTERFACE_DESCRIPTION tls_io_interface =
{
    cord_tls_create,
    cord_tls_destroy,
    cord_tls_open,
    cord_tls_close,
    cord_tls_send,
    cord_tls_process_item,
    cord_tls_query_uri,
    cord_tls_query_port,
    cord_tls_listen
};

const IO_INTERFACE_DESCRIPTION* cord_tls_get_tls_interface(void)
{
    return &tls_io_interface;
}