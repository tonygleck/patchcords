// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/crypto.h"
#include "openssl/opensslv.h"

#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/app_logging.h"
#include "lib-util-c/crt_extensions.h"

#include "patchcords/patchcord_client.h"
#include "patchcords/cord_client.h"

typedef enum SOCKET_STATE_TAG
{
    IO_STATE_IDLE,
    IO_STATE_CLOSED,
    IO_STATE_CLOSING,
    IO_STATE_OPENING,
    IO_STATE_OPEN,
    IO_STATE_HANDSHAKE,
    IO_STATE_OPENED,
    IO_STATE_ERROR
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
    void* on_close_ctx;

    SSL_CTX* ssl_ctx;
    SSL* ssl_object;
    CORD_HANDLE underlying_socket;
    const IO_INTERFACE_DESCRIPTION* socket_iface;

    BIO* input_bio;
    BIO* output_bio;

    const char* server_cert;
    const char* certificate;
    const unsigned char* private_key;
} TLS_INSTANCE;

#define SSL_DO_HANDSHAKE_SUCCESS 1
#define READ_BUFFER_SIZE         128

static int write_outgoing_bytes(TLS_INSTANCE* tls_instance, ON_SEND_COMPLETE on_send_complete, void* callback_ctx)
{
    int result;
    size_t pending = BIO_ctrl_pending(tls_instance->output_bio);
    if (pending == 0)
    {
        // Nothing to send
        result = 0;
    }
    else
    {
        unsigned char* bytes_to_send = malloc(pending);
        if (bytes_to_send == NULL)
        {
            log_error("Failure allocating receiving buffer");
            result = __LINE__;
        }
        else
        {
            if (BIO_read(tls_instance->output_bio, bytes_to_send, (int)pending) != (int)pending)
            {
                log_error("BIO_read not in pending state.");
                result = __LINE__;
            }
            else if (tls_instance->socket_iface->interface_impl_send(tls_instance->underlying_socket, bytes_to_send, pending, on_send_complete, callback_ctx) != 0)
            {
                log_error("Failure sending output buffer");
                result = __LINE__;
            }
            else
            {
                result = 0;
            }
            free(bytes_to_send);
        }
    }
    return result;
}

static int add_server_certificates(TLS_INSTANCE* tls_instance)
{
    int result;
#if (OPENSSL_VERSION_NUMBER >= 0x10100000L) && (OPENSSL_VERSION_NUMBER < 0x20000000L)
    const BIO_METHOD* bio_method;
#else
    BIO_METHOD* bio_method;
#endif
    BIO* cert_memory_bio;

    X509_STORE* cert_store = SSL_CTX_get_cert_store(tls_instance->ssl_ctx);
    if (cert_store == NULL)
    {
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    else if ((bio_method = BIO_s_mem()) == NULL)
    {
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    else if ((cert_memory_bio = BIO_new(bio_method)) == NULL)
    {
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    else
    {
        int cert_bio_len = BIO_puts(cert_memory_bio, tls_instance->server_cert);
        if (cert_bio_len < 0)
        {
            log_error("Failure creating bio memory");
            result = __LINE__;
        }
        else if ( (size_t)cert_bio_len != strlen(tls_instance->server_cert))
        {
            log_error("mismatching legths");
            BIO_free(cert_memory_bio);
            result = __LINE__;
        }
        else
        {
            bool loop_success = true;
            X509* x509_cert;
            while ((x509_cert = PEM_read_bio_X509(cert_memory_bio, NULL, NULL, NULL)) != NULL)
            {
                if (!X509_STORE_add_cert(cert_store, x509_cert))
                {
                    X509_free(x509_cert);
                    log_error("failure in X509_STORE_add_cert");
                    loop_success = false;
                    break;
                }
                X509_free(x509_cert);
            }
            result = loop_success ? 0 : __LINE__;
            BIO_free(cert_memory_bio);
        }
    }
    return result;
}

static void send_tls_handshake(TLS_INSTANCE* tls_instance)
{
    // ERR_clear_error must be called before any call that might set an
    // SSL_get_error result
    ERR_clear_error();
    int result = SSL_do_handshake(tls_instance->ssl_object);
    if (result != SSL_DO_HANDSHAKE_SUCCESS)
    {
        result = SSL_get_error(tls_instance->ssl_object, result);
        if (result != SSL_ERROR_WANT_READ && result != SSL_ERROR_WANT_WRITE)
        {
            if (result == SSL_ERROR_SSL)
            {
                log_error("%s", ERR_error_string(ERR_get_error(), NULL));
            }
            else
            {
                log_error("SSL handshake failed: %d", result);
            }
            tls_instance->current_state = IO_STATE_ERROR;
        }
        else
        {
            if (write_outgoing_bytes(tls_instance, NULL, NULL) != 0)
            {
                log_error("Failure writing outgoing bytes");
                tls_instance->current_state = IO_STATE_ERROR;
            }
        }
    }
    else
    {
        tls_instance->current_state = IO_STATE_OPENED;
        if (tls_instance->on_open_complete != NULL)
        {
            tls_instance->on_open_complete(tls_instance->on_open_complete_ctx, IO_OPEN_OK);
        }
    }
}

static int open_openssl_instance(TLS_INSTANCE* tls_instance)
{
    int result;
    const SSL_METHOD* method = TLS_client_method();
    if ((tls_instance->ssl_ctx = SSL_CTX_new(method)) == NULL)
    {
        log_error("Failure creating ssl context");
        result = __LINE__;
    }
    else if ((tls_instance->input_bio = BIO_new(BIO_s_mem())) == NULL)
    {
        SSL_CTX_free(tls_instance->ssl_ctx);
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    else if ((tls_instance->output_bio = BIO_new(BIO_s_mem())) == NULL)
    {
        (void)BIO_free(tls_instance->input_bio);
        SSL_CTX_free(tls_instance->ssl_ctx);
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    else if (tls_instance->server_cert != NULL && add_server_certificates(tls_instance))
    {
        (void)BIO_free(tls_instance->input_bio);
        (void)BIO_free(tls_instance->output_bio);
        SSL_CTX_free(tls_instance->ssl_ctx);
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    /*else if (tls_instance->server_cert != NULL && tls_instance->private_key && add_client_certificates(tls_instance) != 0)
    {
        (void)BIO_free(tls_instance->input_bio);
        (void)BIO_free(tls_instance->output_bio);
        SSL_CTX_free(tls_instance->ssl_ctx);
        log_error("Failure creating bio memory");
        result = __LINE__;
    }*/
    else
    {
        //SSL_CTX_set_cert_verify_callback(tlsInstance->ssl_context, tlsInstance->tls_validation_callback, tlsInstance->tls_validation_callback_data);
        SSL_CTX_set_verify(tls_instance->ssl_ctx, SSL_VERIFY_PEER, NULL);
        if ((tls_instance->ssl_object = SSL_new(tls_instance->ssl_ctx)) == NULL)
        {
            (void)BIO_free(tls_instance->input_bio);
            (void)BIO_free(tls_instance->output_bio);
            SSL_CTX_free(tls_instance->ssl_ctx);
            log_error("Failure creating bio memory");
            result = __LINE__;
        }
        else
        {
            SSL_set_bio(tls_instance->ssl_object, tls_instance->input_bio, tls_instance->output_bio);
            SSL_set_connect_state(tls_instance->ssl_object);
            result = 0;
        }

    }
    return result;
}

static int initialize_openssl(void)
{
    int result = 0;
    //(void)SSL_library_init();
    //SSL_load_error_strings();
    ERR_load_BIO_strings();
    //OpenSSL_add_all_algorithms();

    // if (openssl_static_locks_install() != 0)
    // {
    //     log_error("Failed to install static locks in OpenSSL!");
    //     result = __LINE__;
    // }
    // else
    // {
    //     openssl_dynamic_locks_install();
    // }
    return result;
}

static void deinitialize_openssl(void)
{
#if  (OPENSSL_VERSION_NUMBER >= 0x00907000L) &&  (OPENSSL_VERSION_NUMBER < 0x20000000L) && (FIPS_mode_set)
    FIPS_mode_set(0);
#endif
    //CRYPTO_set_locking_callback(NULL);
    //CRYPTO_set_id_callback(NULL);
    //ERR_free_strings();
    //EVP_cleanup();
#if   (OPENSSL_VERSION_NUMBER < 0x10000000L)
    ERR_remove_state(0);
#elif (OPENSSL_VERSION_NUMBER < 0x10100000L) || (OPENSSL_VERSION_NUMBER >= 0x20000000L)
    ERR_remove_thread_state(NULL);
#endif
#if  (OPENSSL_VERSION_NUMBER >= 0x10002000L) &&  (OPENSSL_VERSION_NUMBER < 0x10010000L) && (SSL_COMP_free_compression_methods)
    SSL_COMP_free_compression_methods();
#endif
    CRYPTO_cleanup_all_ex_data();
}

// Callbacks
static void on_socket_open_complete(void* ctx, IO_OPEN_RESULT open_result)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (open_result != IO_OPEN_OK)
    {
        if (tls_instance->current_state == IO_STATE_OPENING)
        {
            tls_instance->current_state = IO_STATE_HANDSHAKE;
        }
    }
    else
    {
        log_error("Failure opening socket");
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

void on_socket_send_complete(void* ctx, IO_SEND_RESULT send_result)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
    }
}

void on_socket_bytes_recv(void* ctx, const unsigned char* buffer, size_t size)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
        int written = BIO_write(tls_instance->input_bio, buffer, (int)size);
        if (written != (int)size)
        {
            log_error("Failure decrypting incoming buffer");
            tls_instance->current_state = IO_STATE_ERROR;
        }
        else
        {
            if (tls_instance->current_state == IO_STATE_HANDSHAKE)
            {
                send_tls_handshake(tls_instance);
            }
            else if (tls_instance->current_state == IO_STATE_OPENED)
            {
                int recv_bytes;
                unsigned char read_buffer[READ_BUFFER_SIZE];
                do
                {
                    if ((recv_bytes = SSL_read(tls_instance->ssl_object, read_buffer, sizeof(read_buffer))) > 0)
                    {
                        if (tls_instance->on_bytes_received != NULL)
                        {
                            tls_instance->on_bytes_received(tls_instance->on_bytes_received_ctx, read_buffer, recv_bytes);
                        }
                    }
                } while (recv_bytes > 0);
            }
        }
    }
}

static void on_socket_error(void* ctx, IO_ERROR_RESULT error_result)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
    }
}

static int create_underlying_socket(TLS_INSTANCE* tls_instance, const TLS_CONFIG* config)
{
    int result;
    if ((tls_instance->socket_iface = xio_cord_get_interface()) == NULL)
    {
        log_error("Failure xio_cord_get_interface return NULL");
        result = __LINE__;
    }
    else if ((tls_instance->underlying_socket = tls_instance->socket_iface->interface_impl_create(config->socket_config, on_socket_bytes_recv, tls_instance, on_socket_error, tls_instance)) != NULL)
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

CORD_HANDLE cord_client_create(const void* parameters, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_ctx, ON_IO_ERROR on_error, void* on_error_ctx)
{
    TLS_INSTANCE* result;
    if (parameters == NULL)
    {
        log_error("Invalid parameter specified");
        result = NULL;
    }
    else if (initialize_openssl() != 0)
    {
        log_error("Failure initializing openssl");
    }
    else if ((result = malloc(sizeof(TLS_INSTANCE))) == NULL)
    {
        log_error("Failure allocating tls instance");
    }
    // Open the underlying socket
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
        // Copy the host name
        else if (clone_string(&result->hostname, config->hostname) != 0)
        {
            log_error("Failure cloning hostname value");
            result->socket_iface->interface_impl_destroy(result->underlying_socket);
            free(result);
            result = NULL;
        }
        else
        {
            result->on_bytes_received = on_bytes_received;
            result->on_bytes_received_ctx = on_bytes_received_ctx;
            result->on_error = on_error;
            result->on_error_ctx = on_error_ctx;
            result->port = config->port;
        }
    }
    return (CORD_HANDLE)result;
}

void cord_client_destroy(CORD_HANDLE handle)
{
    if (handle != NULL)
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        tls_instance->socket_iface->interface_impl_destroy(tls_instance->underlying_socket);
        (void)BIO_free(tls_instance->input_bio);
        (void)BIO_free(tls_instance->output_bio);
        SSL_CTX_free(tls_instance->ssl_ctx);

        deinitialize_openssl();
        free(tls_instance->hostname);
        free(tls_instance);
    }
}

int cord_client_open(CORD_HANDLE handle, ON_IO_OPEN_COMPLETE on_open_complete, void* on_open_complete_ctx)
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
        if (tls_instance->current_state == IO_STATE_OPEN || tls_instance->current_state == IO_STATE_OPENING || tls_instance->current_state == IO_STATE_OPEN)
        {
            log_error("TLS Connection is in invalid state to open");
            result = __LINE__;
        }
        else if (open_openssl_instance(tls_instance) != 0)
        {
            log_error("Socket is in invalid state to open");
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

int cord_client_listen(CORD_HANDLE handle, ON_INCOMING_CONNECT incoming_conn_cb, void* user_ctx)
{
    uint16_t result;
    if (handle == NULL || incoming_conn_cb == NULL)
    {
        log_error("Failure invalid parameter specified handle: %p, incoming_conn_cb: %p", handle, incoming_conn_cb);
        result = __LINE__;
    }
    else
    {
        // TODO: Setup listening TLS info
        result = __LINE__;
    }
    return result;
}

int cord_client_close(CORD_HANDLE handle, ON_IO_CLOSE_COMPLETE on_close_complete, void* callback_ctx)
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
        if (tls_instance->current_state == IO_STATE_CLOSED || tls_instance->current_state == IO_STATE_CLOSING)
        {
            log_error("Failure can not close while already closing");
            result = __LINE__;
        }
        else
        {
            TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
            tls_instance->on_close_complete = on_close_complete;
            tls_instance->on_close_ctx = callback_ctx;
            tls_instance->current_state = IO_STATE_CLOSING;

            if (tls_instance->current_state == IO_STATE_OPENING || tls_instance->current_state == IO_STATE_OPEN)
            {
                tls_instance->on_open_complete(tls_instance->on_open_complete_ctx, IO_OPEN_CANCELLED);
            }

            if (tls_instance->socket_iface->interface_impl_close(tls_instance->underlying_socket, on_socket_close_complete, tls_instance) != 0)
            {
                log_error("Failure attempting to close socket");
                result = __LINE__;
            }
            else
            {
                result = 0;
            }
        }
    }
    return result;
}

int cord_client_send(CORD_HANDLE handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    if (handle == NULL)
    {
        log_error("Invalid parameter specified");
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
        else if (SSL_write(tls_instance->ssl_object, buffer, (int)size) != (int)size)
        {
            log_error("Failure encrypting sending buffer");
            result =__LINE__;
        }
        else if (write_outgoing_bytes(tls_instance, on_send_complete, callback_context) != 0)
        {
            log_error("Failure writing outgoig bytes");
            result =__LINE__;
        }
        else
        {
            result = 0;
        }

    }
    return result;
}

void cord_client_process_item(CORD_HANDLE handle)
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
                send_tls_handshake(tls_instance);
                break;
            case IO_STATE_CLOSED:
                if (tls_instance->on_close_complete != NULL)
                {
                    tls_instance->on_close_complete(tls_instance->on_close_ctx);
                }
                break;
            case IO_STATE_OPENING:
            case IO_STATE_CLOSING:
            case IO_STATE_OPENED:
            case IO_STATE_IDLE:
                break;
            case IO_STATE_ERROR:
                break;
        }
        tls_instance->socket_iface->interface_impl_process_item(tls_instance->underlying_socket);
    }
}

int cord_client_set_certificate(CORD_HANDLE handle, const char* certificate, const unsigned char* private_key)
{
    int result;
    if (handle == NULL || certificate == NULL || private_key == NULL)
    {
        log_error("Invalid parameter handle: %p, certificate: %p, private_key: %p", handle, certificate, private_key);
        result == __LINE__;
    }
    else
    {
        TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
        if (tls_instance->current_state == IO_STATE_OPEN || tls_instance->current_state == IO_STATE_OPENED || tls_instance->current_state == IO_STATE_HANDSHAKE)
        {
            log_error("Invalid state to set certificate");
            result == __LINE__;
        }
        else
        {
            TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)handle;
            tls_instance->certificate = certificate;
            tls_instance->private_key = private_key;
            result = 0;
        }
    }
    return result;
}

const char* cord_client_query_uri(CORD_HANDLE handle)
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

uint16_t cord_client_query_port(CORD_HANDLE handle)
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
    cord_client_create,
    cord_client_destroy,
    cord_client_open,
    cord_client_close,
    cord_client_send,
    cord_client_process_item,
    cord_client_query_uri,
    cord_client_query_port,
    cord_client_listen
};

const IO_INTERFACE_DESCRIPTION* xio_cord_get_interface(void)
{
    return &tls_io_interface;
}