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
#include "patchcords/cord_tls_client.h"

typedef enum SOCKET_STATE_TAG
{
    IO_STATE_IDLE,
    IO_STATE_CLOSED,
    IO_STATE_CLOSING,
    IO_STATE_OPENING,
    IO_STATE_OPEN_ERROR,
    IO_STATE_OPEN,
    IO_STATE_HANDSHAKE,
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
        unsigned char* bytes_to_send = (unsigned char*)malloc(pending);
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

static X509* create_x509_bio(const char* certificate, BIO** out_bio, bool use_aux)
{
    X509* result;
    BIO* bio;
    if ((bio = BIO_new_mem_buf((char*)certificate, -1)) == NULL)
    {
        log_error("Failure loading the certificate file");
        result = NULL;
    }
    else
    {
        if (use_aux)
        {
            if ((result = PEM_read_bio_X509_AUX(bio, NULL, NULL, NULL)) == NULL)
            {
                log_error("Failure creating private key evp_key");
            }
        }
        else
        {
            if ((result = PEM_read_bio_X509(bio, NULL, NULL, NULL)) == NULL)
            {
                log_error("Failure reading certificate into bio");
            }
        }
        if (result != NULL)
        {
            if (out_bio == NULL)
            {
                BIO_free(bio);
            }
            else
            {
                *out_bio = bio;
            }
        }
    }
    return result;
}

static EVP_PKEY* create_pkey_object(const char* private_key)
{
    EVP_PKEY* result;
    BIO* bio = BIO_new_mem_buf(private_key, -1);
    if (bio == NULL)
    {
        log_error("Failure loading the certificate file");
        result = NULL;
    }
    else
    {
        if ((result = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL)) == NULL)
        {
            log_error("Failure creating private key evp_key");
        }
    }
    return result;
}

static int add_client_certificates(TLS_INSTANCE* tls_instance)
{
    int result;
    EVP_PKEY* evp_key;
    BIO* bio_cert;
    X509* x509_cert;
    // Load the private key
    if ((evp_key = create_pkey_object(tls_instance->private_key)) == NULL)
    {
        log_error("Failure loading the private key");
        result = __LINE__;
    }
    else if ((x509_cert = create_x509_bio(tls_instance->certificate, &bio_cert, true)) == NULL)
    {
        log_error("Failure loading the certificate");
        result = __LINE__;
    }
    else
    {
        if (SSL_CTX_use_PrivateKey(tls_instance->ssl_ctx, evp_key) <= 0)
        {
            log_error("Failure loading the private key");
            result = __LINE__;
        }
        else if (SSL_CTX_use_certificate(tls_instance->ssl_ctx, x509_cert) != 1)
        {
            log_error("Failure loading the private key");
            result = __LINE__;
        }
        else
        {
            X509* ca_chain;
            result = 0;
            // If we could set up our certificate, now proceed to the CA
            // certificates.

            SSL_CTX_clear_extra_chain_certs(tls_instance->ssl_ctx);
            while ((ca_chain = PEM_read_bio_X509(bio_cert, NULL, NULL, NULL)) != NULL)
            {
                if (SSL_CTX_add_extra_chain_cert(tls_instance->ssl_ctx, ca_chain) != 1)
                {
                    log_error("Failure adding certificate chain to stream");
                    X509_free(ca_chain);
                    result = __LINE__;
                    break;
                }
            }
        }
        EVP_PKEY_free(evp_key);
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
    else if ((cert_memory_bio = BIO_new_mem_buf((char*)tls_instance->certificate, -1)) == NULL)
    {
        log_error("Failure creating bio memory");
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

static int load_certificates(TLS_INSTANCE* tls_instance)
{
    int result;
    X509* x509_cert = create_x509_bio(tls_instance->certificate, NULL, false);
    if (x509_cert == NULL)
    {
        log_error("Failure reading certificate into bio");
        //ERR_print_errors_fp(stderr);
        result = __LINE__;
    }
    else if (SSL_CTX_use_certificate(tls_instance->ssl_ctx, x509_cert) <= 0)
    {
        log_error("Failure loading the certificate file");
        X509_free(x509_cert);
        result = __LINE__;
    }
    else
    {
        EVP_PKEY* evp_key;
        if ((evp_key = create_pkey_object(tls_instance->private_key)) == NULL)
        {
            log_error("Failure loading the private key");
            result = __LINE__;
        }
        else
        {
            // set the private key from KeyFile (may be the same as CertFile)
            if (SSL_CTX_use_PrivateKey(tls_instance->ssl_ctx, evp_key) <= 0)
            {
                //ERR_print_errors_fp(stderr);
                log_error("Failure using the private key");
                result = __LINE__;
            }
            // verify private key
            else if (!SSL_CTX_check_private_key(tls_instance->ssl_ctx) )
            {
                //fprintf(stderr, "Private key does not match the public certificate\n");
                log_error("Failure validating private key against the public certificate");
                result = __LINE__;
            }
            else
            {
                result = 0;
            }
            EVP_PKEY_free(evp_key);
        }
        X509_free(x509_cert);
    }
    return result;
}

static int create_ssl_ctx(TLS_INSTANCE* tls_instance)
{
    int result;
    const SSL_METHOD* method = TLS_client_method();
    if ((tls_instance->ssl_ctx = SSL_CTX_new(method)) == NULL)
    {
        log_error("Failure creating ssl context");
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}

static void close_openssl_instance(TLS_INSTANCE* tls_instance)
{
    SSL_free(tls_instance->ssl_object);
    if (tls_instance->input_bio != NULL)
    {
        (void)BIO_free(tls_instance->input_bio);
        tls_instance->input_bio = NULL;
    }
    if (tls_instance->output_bio != NULL)
    {
        (void)BIO_free(tls_instance->output_bio);
        tls_instance->output_bio = NULL;
    }
    if (tls_instance->ssl_ctx != NULL)
    {
        SSL_CTX_free(tls_instance->ssl_ctx);
    }
}

static int open_openssl_instance(TLS_INSTANCE* tls_instance)
{
    int result;
    if (create_ssl_ctx(tls_instance) != 0)
    {
        log_error("Failure creating ssl context");
        result = __LINE__;
    }
    else if ((tls_instance->input_bio = BIO_new(BIO_s_mem())) == NULL)
    {
        SSL_CTX_free(tls_instance->ssl_ctx);
        tls_instance->ssl_ctx = NULL;
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    else if ((tls_instance->output_bio = BIO_new(BIO_s_mem())) == NULL)
    {
        (void)BIO_free(tls_instance->input_bio);
        SSL_CTX_free(tls_instance->ssl_ctx);
        tls_instance->ssl_ctx = NULL;
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    else if (tls_instance->server_cert != NULL && add_server_certificates(tls_instance))
    {
        (void)BIO_free(tls_instance->input_bio);
        (void)BIO_free(tls_instance->output_bio);
        SSL_CTX_free(tls_instance->ssl_ctx);
        tls_instance->ssl_ctx = NULL;
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    else if (tls_instance->certificate != NULL && tls_instance->private_key && add_client_certificates(tls_instance) != 0)
    {
        (void)BIO_free(tls_instance->input_bio);
        (void)BIO_free(tls_instance->output_bio);
        SSL_CTX_free(tls_instance->ssl_ctx);
        log_error("Failure creating bio memory");
        result = __LINE__;
    }
    else
    {
        //SSL_CTX_set_cert_verify_callback(tlsInstance->ssl_context, tlsInstance->tls_validation_callback, tlsInstance->tls_validation_callback_data);
        SSL_CTX_set_verify(tls_instance->ssl_ctx, SSL_VERIFY_PEER, NULL);
        if ((tls_instance->ssl_object = SSL_new(tls_instance->ssl_ctx)) == NULL)
        {
            (void)BIO_free(tls_instance->input_bio);
            (void)BIO_free(tls_instance->output_bio);
            SSL_CTX_free(tls_instance->ssl_ctx);
            tls_instance->ssl_ctx = NULL;
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

void on_socket_send_complete(void* ctx, IO_SEND_RESULT send_result)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
    }
}

void on_socket_bytes_recv(void* ctx, const unsigned char* buffer, size_t size, const void* config)
{
    TLS_INSTANCE* tls_instance = (TLS_INSTANCE*)ctx;
    if (tls_instance != NULL)
    {
        int written = BIO_write(tls_instance->input_bio, buffer, (int)size);
        if (written != (int)size)
        {
            log_error("Failure decrypting incoming buffer of size %zu", size);
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
                            tls_instance->on_bytes_received(tls_instance->on_bytes_received_ctx, read_buffer, recv_bytes, config);
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
        tls_instance->on_error(tls_instance->on_error_ctx, error_result);
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
    else if (initialize_openssl() != 0)
    {
        log_error("Failure initializing openssl");
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

        deinitialize_openssl();
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
        if (create_ssl_ctx(tls_instance) != 0)
        {
            log_error("Failure creating ssl context");
            result = __LINE__;
        }
        else if (load_certificates(tls_instance) != 0)
        {
            log_error("Failure loadding certificates");
            SSL_CTX_free(tls_instance->ssl_ctx);
            tls_instance->ssl_ctx = NULL;
            result = __LINE__;
        }
        else if (tls_instance->socket_iface->interface_impl_listen(tls_instance->underlying_socket, incoming_conn_cb, user_ctx) != 0)
        {
            log_error("Failure Listening on socket");
            SSL_CTX_free(tls_instance->ssl_ctx);
            tls_instance->ssl_ctx = NULL;
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
            close_openssl_instance(tls_instance);
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
                send_tls_handshake(tls_instance);
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
                break;
            case IO_STATE_OPEN_ERROR:
                if (tls_instance->on_open_complete != NULL)
                {
                    tls_instance->on_open_complete(tls_instance->on_open_complete_ctx, IO_OPEN_ERROR);
                }
                // Close from a partial open
                close_openssl_instance(tls_instance);
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