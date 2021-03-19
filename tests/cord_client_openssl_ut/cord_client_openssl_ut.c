// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#else
#include <stdlib.h>
#include <stddef.h>
#endif

#include <errno.h>
#include "ctest.h"
#include "azure_macro_utils/macro_utils.h"
#include "umock_c/umock_c.h"

#include "umock_c/umock_c_negative_tests.h"
#include "umock_c/umocktypes_charptr.h"

static void* my_mem_shim_malloc(size_t size)
{
    return malloc(size);
}

static void my_mem_shim_free(void* ptr)
{
    free(ptr);
}

#define ENABLE_MOCKS
#include "patchcords/patchcord_client.h"
#include "umock_c/umock_c_prod.h"
#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/crt_extensions.h"

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/crypto.h"
#include "openssl/opensslv.h"

MOCKABLE_FUNCTION(, void, test_on_bytes_recv, void*, context, const unsigned char*, buffer, size_t, size, const void*, config);
MOCKABLE_FUNCTION(, void, test_on_send_complete, void*, context, IO_SEND_RESULT, send_result);
MOCKABLE_FUNCTION(, void, test_on_open_complete, void*, context, IO_OPEN_RESULT, open_result);
MOCKABLE_FUNCTION(, void, test_on_close_complete, void*, context);
MOCKABLE_FUNCTION(, void, test_on_error, void*, context, IO_ERROR_RESULT, error_result);
MOCKABLE_FUNCTION(, void, test_on_accept_conn, void*, context, const void*, config);
MOCKABLE_FUNCTION(, void, test_on_client_close, void*, context);

MOCKABLE_FUNCTION(, CORD_HANDLE, interface_socket_create, const void*, io_create_parameters, const PATCHCORD_CALLBACK_INFO*, client_cb);
MOCKABLE_FUNCTION(, void, interface_socket_destroy, CORD_HANDLE, impl_handle);
MOCKABLE_FUNCTION(, int, interface_socket_close, CORD_HANDLE, impl_handle, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, interface_socket_open, CORD_HANDLE, impl_handle, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_ctx);

// OpenSSL functions
#if OPENSSL_VERSION_NUMBER >= 0x1010007fL
MOCKABLE_FUNCTION(, BIO*, BIO_new, const BIO_METHOD*, type);
MOCKABLE_FUNCTION(, const BIO_METHOD*, BIO_s_mem);
#else
MOCKABLE_FUNCTION(, BIO*, BIO_new, BIO_METHOD*, type);
MOCKABLE_FUNCTION(, BIO_METHOD*, BIO_s_mem);
#endif
MOCKABLE_FUNCTION(, int, BIO_puts, BIO*, bp, const char*, buf);
MOCKABLE_FUNCTION(, int, ERR_load_BIO_strings);
MOCKABLE_FUNCTION(, int, BIO_free, BIO*, b);
#if OPENSSL_VERSION_NUMBER >= 0x1000207fL
MOCKABLE_FUNCTION(, BIO*, BIO_new_mem_buf, const void*, buf, int, len);
#else
MOCKABLE_FUNCTION(, BIO*, BIO_new_mem_buf, void*, buf, int, len);
#endif
MOCKABLE_FUNCTION(, size_t, BIO_ctrl_pending, BIO*, b);
MOCKABLE_FUNCTION(, int, BIO_read, BIO*, b, void*, data, int, dlen);
MOCKABLE_FUNCTION(, int, BIO_write, BIO*, b, const void*, data, int, dlen);

MOCKABLE_FUNCTION(, X509*, PEM_read_bio_X509, BIO*, bp, X509**, x, pem_password_cb*, cb, void*, u);
MOCKABLE_FUNCTION(, RSA*, PEM_read_bio_RSAPrivateKey, BIO*, bp, RSA**, x, pem_password_cb*, cb, void*, u);
MOCKABLE_FUNCTION(, EVP_PKEY*, PEM_read_bio_PrivateKey, BIO*, bp, EVP_PKEY**, x, pem_password_cb*, cb, void*, u);
MOCKABLE_FUNCTION(, X509*, PEM_read_bio_X509_AUX, BIO*, bp, X509**, x, pem_password_cb*, cb, void*, u);

MOCKABLE_FUNCTION(, int, X509_STORE_add_cert, X509_STORE*, ctx, X509*, x);
MOCKABLE_FUNCTION(, void, X509_free, X509*, a);

MOCKABLE_FUNCTION(, void, ERR_clear_error);
MOCKABLE_FUNCTION(, char*, ERR_error_string, unsigned long, e, char*, buf);
MOCKABLE_FUNCTION(, unsigned long, ERR_get_error);

MOCKABLE_FUNCTION(, const SSL_METHOD*, TLS_server_method);
MOCKABLE_FUNCTION(, const SSL_METHOD*, TLS_client_method);

MOCKABLE_FUNCTION(, void, SSL_set_bio, SSL*, s, BIO*, rbio, BIO*, wbio);
MOCKABLE_FUNCTION(, void, SSL_set_connect_state, SSL*, s);
MOCKABLE_FUNCTION(, int, SSL_do_handshake, SSL*, s);
MOCKABLE_FUNCTION(, int, SSL_get_error, const SSL*, s, int, ret_code);
MOCKABLE_FUNCTION(, SSL*, SSL_new, SSL_CTX*, ctx);
MOCKABLE_FUNCTION(, void, SSL_free, SSL*, ssl);
MOCKABLE_FUNCTION(, int, SSL_write, SSL*, ssl, const void*, buf, int, num);
MOCKABLE_FUNCTION(, int, SSL_read, SSL*, ssl, void*, buf, int, num);
MOCKABLE_FUNCTION(, void, SSL_CTX_free, SSL_CTX*, ctx);
MOCKABLE_FUNCTION(, X509_STORE*, SSL_CTX_get_cert_store, const SSL_CTX*, ctx);
MOCKABLE_FUNCTION(, SSL_CTX*, SSL_CTX_new, const SSL_METHOD*, meth);
MOCKABLE_FUNCTION(, void, SSL_CTX_set_verify, SSL_CTX*, ctx, int, mode, SSL_verify_cb, callback);
MOCKABLE_FUNCTION(, int, SSL_CTX_use_certificate, SSL_CTX*, ctx, X509*, x);
MOCKABLE_FUNCTION(, int, SSL_CTX_use_PrivateKey, SSL_CTX*, ctx, EVP_PKEY*, pkey);
MOCKABLE_FUNCTION(, int, SSL_CTX_check_private_key, const SSL_CTX*, ctx);
MOCKABLE_FUNCTION(, long, SSL_CTX_ctrl, SSL_CTX*, ctx, int, cmd, long, larg, void*, parg);

MOCKABLE_FUNCTION(, void, EVP_PKEY_free, EVP_PKEY*, pkey);

/*
MOCKABLE_FUNCTION(, int, socket_open, CORD_HANDLE, impl_handle, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_ctx);
MOCKABLE_FUNCTION(, int, interface_socket_close, CORD_HANDLE, impl_handle, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, socket_send, CORD_HANDLE, impl_handle, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_ctx);
MOCKABLE_FUNCTION(, void, socket_process_item, CORD_HANDLE, impl_handle);
MOCKABLE_FUNCTION(, const char*, socket_query_uri, CORD_HANDLE, impl_handle);
MOCKABLE_FUNCTION(, uint16_t, socket_query_port, CORD_HANDLE, impl_handle);
MOCKABLE_FUNCTION(, int, socket_listen, CORD_HANDLE, impl_handle, ON_INCOMING_CONNECT, incoming_conn, void*, user_ctx);*/

#undef ENABLE_MOCKS

#include "patchcords/cord_tls_client.h"

static const char* TEST_HOSTNAME = "test.hostname.com";
static size_t TEST_SEND_BUFFER_LEN = 16;
static uint16_t TEST_PORT_VALUE = 8543;

static unsigned char g_send_buffer[] = { 0x25, 0x26, 0x26, 0x28, 0x29 };
static unsigned char g_recv_buffer[] = { 0x52, 0x62, 0x88, 0x52, 0x59 };
static size_t g_buffer_len = 5;
static void* TEST_USER_CONTEXT_VALUE = (void*)0x08765432;
static void* TEST_SOCKET_CONFIG = (void*)0x12345678;

static bool g_fail_socket_call;

static ON_IO_OPEN_COMPLETE g_on_open_complete;
static void* g_on_open_ctx;
static ON_IO_CLOSE_COMPLETE g_on_close_complete;
static void* g_on_close_ctx;

#define ACCEPT_SOCKET_NUMBER    11
#define SOCKET_NUMBER           24

#ifdef __cplusplus
extern "C" {
#endif
    static int my_clone_string(char** target, const char* source)
    {
        size_t len = strlen(source);
        *target = my_mem_shim_malloc(len+1);
        strcpy(*target, source);
        return 0;
    }

    static int socket_close(CORD_HANDLE impl_handle, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
    {
        (void)impl_handle;
        (void)on_io_close_complete;
        (void)callback_context;
        return 0;
    }

    static int socket_send(CORD_HANDLE impl_handle, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_ctx)
    {
        (void)buffer;
        (void)size;
        (void)on_send_complete;
        (void)callback_ctx;
        (void)impl_handle;
        return 0;
    }

    static void socket_process_item(CORD_HANDLE impl_handle)
    {
        (void)impl_handle;
    }

    static const char* socket_query_uri(CORD_HANDLE impl_handle)
    {
        (void)impl_handle;
        return "NULL";
    }

    static uint16_t socket_query_port(CORD_HANDLE impl_handle)
    {
        (void)impl_handle;
        return 123;
    }

    static int socket_listen(CORD_HANDLE impl_handle, ON_INCOMING_CONNECT incoming_conn, void* user_ctx)
    {
        (void)impl_handle;
        (void)incoming_conn;
        (void)user_ctx;
        return 0;
    }

    static SSL* my_SSL_new(SSL_CTX* ctx)
    {
        return (SSL*)my_mem_shim_malloc(1);
    }

    static void my_SSL_free(SSL* ssl)
    {
        my_mem_shim_free(ssl);
    }

    static SSL_CTX* my_SSL_CTX_new(const SSL_METHOD* meth)
    {
        (void)meth;
        return (SSL_CTX*)my_mem_shim_malloc(1);
    }

    static void my_SSL_CTX_free(SSL_CTX* ctx)
    {
        my_mem_shim_free(ctx);
    }

    static BIO* my_BIO_new(const BIO_METHOD* type)
    {
        (void)type;
        return (BIO*)my_mem_shim_malloc(1);
    }

    static int my_BIO_free(BIO* a)
    {
        my_mem_shim_free(a);
    }

    static CORD_HANDLE my_interface_socket_create(const void* xio_create_parameters, const PATCHCORD_CALLBACK_INFO* client_cb)
    {
        CORD_HANDLE result;
        (void)xio_create_parameters;
        (void)client_cb;
        if (g_fail_socket_call)
        {
            result = NULL;
        }
        else
        {
            result = (CORD_HANDLE)my_mem_shim_malloc(1);
        }
        return result;
    }

    static void my_interface_socket_destroy(CORD_HANDLE handle)
    {
        my_mem_shim_free(handle);
    }

    static int my_interface_socket_open(CORD_HANDLE impl_handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_ctx)
    {
        (void)impl_handle;
        g_on_open_complete = on_io_open_complete;
        g_on_open_ctx = on_io_open_complete_ctx;
        return 0;
    }

    static int my_interface_socket_close(CORD_HANDLE impl_handle, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* callback_context)
    {
        g_on_close_complete = on_io_close_complete;
        g_on_close_ctx = callback_context;
        return 0;
    }


#ifdef __cplusplus
}
#endif

const IO_INTERFACE_DESCRIPTION socket_desc =
{
    interface_socket_create,
    interface_socket_destroy,
    interface_socket_open,
    interface_socket_close,
    socket_send,
    socket_process_item,
    socket_query_uri,
    socket_query_port,
    socket_listen
};

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    CTEST_ASSERT_FAIL("umock_c reported error: %s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

CTEST_BEGIN_TEST_SUITE(cord_tls_openssl_ut)

CTEST_SUITE_INITIALIZE()
{
    umock_c_init(on_umock_c_error);

    REGISTER_UMOCK_ALIAS_TYPE(CORD_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(IO_OPEN_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_SEND_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_ERROR_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(ssize_t, long);
    REGISTER_UMOCK_ALIAS_TYPE(PATCH_INSTANCE_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_CLOSE_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(SSL_verify_cb, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_BYTES_RECEIVED, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_ERROR, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_OPEN_COMPLETE, void*);

    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_malloc, my_mem_shim_malloc);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mem_shim_malloc, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_free, my_mem_shim_free);

    REGISTER_GLOBAL_MOCK_HOOK(clone_string, my_clone_string);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(clone_string, __LINE__);

    REGISTER_GLOBAL_MOCK_HOOK(SSL_new, my_SSL_new);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(SSL_new, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(SSL_free, my_SSL_free);
    REGISTER_GLOBAL_MOCK_HOOK(SSL_CTX_new, my_SSL_CTX_new);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(SSL_CTX_new, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(SSL_CTX_free, my_SSL_CTX_free);
    REGISTER_GLOBAL_MOCK_RETURN(SSL_do_handshake, 1);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(SSL_do_handshake, __LINE__);

    REGISTER_GLOBAL_MOCK_HOOK(BIO_new, my_BIO_new);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(BIO_new, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(BIO_free, my_BIO_free);

    REGISTER_GLOBAL_MOCK_HOOK(interface_socket_create, my_interface_socket_create);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(interface_socket_create, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(interface_socket_destroy, my_interface_socket_destroy);
    REGISTER_GLOBAL_MOCK_HOOK(interface_socket_open, my_interface_socket_open);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(interface_socket_open, __LINE__);
    REGISTER_GLOBAL_MOCK_HOOK(interface_socket_close, my_interface_socket_close);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(interface_socket_close, __LINE__);

    //REGISTER_GLOBAL_MOCK_RETURN(cord_socket_get_interface, io_interface_description);
    //REGISTER_GLOBAL_MOCK_FAIL_RETURN(cord_socket_get_interface, NULL);
    //REGISTER_GLOBAL_MOCK_RETURN(socket_create, my_socket_create);
    //REGISTER_GLOBAL_MOCK_FAIL_RETURN(socket_create, NULL);
    //REGISTER_GLOBAL_MOCK_RETURN(socket_destroy, my_socket_destroy);
    //REGISTER_GLOBAL_MOCK_FAIL_RETURN(socket_destroy, NULL);
}

CTEST_SUITE_CLEANUP()
{
    umock_c_deinit();
}

CTEST_FUNCTION_INITIALIZE()
{
    umock_c_reset_all_calls();
    g_fail_socket_call = false;
    g_on_open_complete = NULL;
    g_on_open_ctx = NULL;

    g_on_close_complete = NULL;
    g_on_close_ctx = NULL;

}

CTEST_FUNCTION_CLEANUP()
{
}

static CORD_HANDLE initialize_handle(void)
{
    TLS_CONFIG tls_config = {0};
    PATCHCORD_CALLBACK_INFO callback_info = { test_on_bytes_recv, NULL, test_on_error, NULL, test_on_client_close, TEST_USER_CONTEXT_VALUE };
    tls_config.hostname = TEST_HOSTNAME;
    tls_config.port = TEST_PORT_VALUE;
    tls_config.socket_config = TEST_SOCKET_CONFIG;
    tls_config.socket_desc = &socket_desc;
    return cord_tls_create(&tls_config, &callback_info);
}
static void setup_cord_tls_create_mocks(void)
{
    STRICT_EXPECTED_CALL(ERR_load_BIO_strings()).CallCannotFail();
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    //STRICT_EXPECTED_CALL(cord_socket_get_interface());
    STRICT_EXPECTED_CALL(interface_socket_create(IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(clone_string(IGNORED_ARG, IGNORED_ARG));
}

static void setup_cord_tls_open_mocks(void)
{
    STRICT_EXPECTED_CALL(TLS_client_method()).CallCannotFail();
    STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_s_mem()).CallCannotFail();
    STRICT_EXPECTED_CALL(BIO_new(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_s_mem()).CallCannotFail();
    STRICT_EXPECTED_CALL(BIO_new(IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_CTX_set_verify(IGNORED_ARG, IGNORED_ARG, NULL));
    STRICT_EXPECTED_CALL(SSL_new(IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_set_bio(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_set_connect_state(IGNORED_ARG));
}

static void setup_cord_tls_send_mocks(void)
{
    STRICT_EXPECTED_CALL(SSL_write(IGNORED_ARG, g_send_buffer, g_buffer_len)).SetReturn(g_buffer_len);
    STRICT_EXPECTED_CALL(BIO_ctrl_pending(IGNORED_ARG)).SetReturn(g_buffer_len).CallCannotFail();
    STRICT_EXPECTED_CALL(malloc(g_buffer_len));
    STRICT_EXPECTED_CALL(BIO_read(IGNORED_ARG, IGNORED_ARG, g_buffer_len)).SetReturn(g_buffer_len);
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));
}

CTEST_FUNCTION(cord_tls_create_parameters_NULL_fail)
{
    // arrange
    TLS_CONFIG tls_config = {0};
    tls_config.hostname = TEST_HOSTNAME;
    tls_config.port = TEST_PORT_VALUE;
    tls_config.socket_config = TEST_SOCKET_CONFIG;
    tls_config.socket_desc = &socket_desc;
    PATCHCORD_CALLBACK_INFO callback_info = { test_on_bytes_recv, NULL, test_on_error, NULL, test_on_client_close, TEST_USER_CONTEXT_VALUE };

    // act
    CORD_HANDLE handle = cord_tls_create(NULL, &callback_info);

    // assert
    CTEST_ASSERT_IS_NULL(handle);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_create_succeed)
{
    // arrange
    TLS_CONFIG tls_config = {0};
    tls_config.hostname = TEST_HOSTNAME;
    tls_config.port = TEST_PORT_VALUE;
    tls_config.socket_config = TEST_SOCKET_CONFIG;
    tls_config.socket_desc = &socket_desc;
    PATCHCORD_CALLBACK_INFO callback_info = { test_on_bytes_recv, NULL, test_on_error, NULL, test_on_client_close, TEST_USER_CONTEXT_VALUE };

    setup_cord_tls_create_mocks();

    // act
    CORD_HANDLE handle = cord_tls_create(&tls_config, &callback_info);

    // assert
    CTEST_ASSERT_IS_NOT_NULL(handle);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_create_fail)
{
    // arrange
    TLS_CONFIG tls_config = {0};
    tls_config.hostname = TEST_HOSTNAME;
    tls_config.port = TEST_PORT_VALUE;
    tls_config.socket_config = TEST_SOCKET_CONFIG;
    tls_config.socket_desc = &socket_desc;
    PATCHCORD_CALLBACK_INFO callback_info = { test_on_bytes_recv, NULL, test_on_error, NULL, test_on_client_close, TEST_USER_CONTEXT_VALUE };

    int negativeTestsInitResult = umock_c_negative_tests_init();
    CTEST_ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    setup_cord_tls_create_mocks();

    umock_c_negative_tests_snapshot();

    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (umock_c_negative_tests_can_call_fail(index))
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            // act
            CORD_HANDLE handle = cord_tls_create(&tls_config, &callback_info);

            // assert
            CTEST_ASSERT_IS_NULL(handle);
        }
    }

    // cleanup
    umock_c_negative_tests_deinit();
}

CTEST_FUNCTION(cord_tls_create_socket_interface_NULL_fail)
{
    // arrange
    TLS_CONFIG tls_config = {0};
    tls_config.hostname = TEST_HOSTNAME;
    tls_config.port = TEST_PORT_VALUE;
    tls_config.socket_config = TEST_SOCKET_CONFIG;
    tls_config.socket_desc = NULL;
    PATCHCORD_CALLBACK_INFO callback_info = { test_on_bytes_recv, NULL, test_on_error, NULL, test_on_client_close, TEST_USER_CONTEXT_VALUE };

    STRICT_EXPECTED_CALL(ERR_load_BIO_strings()).CallCannotFail();
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    // act
    CORD_HANDLE handle = cord_tls_create(&tls_config, &callback_info);

    // assert
    CTEST_ASSERT_IS_NULL(handle);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_create_socket_create_NULL_fail)
{
    // arrange
    TLS_CONFIG tls_config = {0};
    tls_config.hostname = TEST_HOSTNAME;
    tls_config.port = TEST_PORT_VALUE;
    tls_config.socket_config = TEST_SOCKET_CONFIG;
    tls_config.socket_desc = &socket_desc;
    PATCHCORD_CALLBACK_INFO callback_info = { test_on_bytes_recv, NULL, test_on_error, NULL, test_on_client_close, TEST_USER_CONTEXT_VALUE };

    STRICT_EXPECTED_CALL(ERR_load_BIO_strings()).CallCannotFail();
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(interface_socket_create(IGNORED_ARG, IGNORED_ARG)).SetReturn(NULL);
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    // act
    CORD_HANDLE handle = cord_tls_create(&tls_config, &callback_info);

    // assert
    CTEST_ASSERT_IS_NULL(handle);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_destroy_succeed)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    umock_c_reset_all_calls();

    // STRICT_EXPECTED_CALL(BIO_free(IGNORED_ARG));
    // STRICT_EXPECTED_CALL(BIO_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(interface_socket_destroy(IGNORED_ARG));
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    // act
    cord_tls_destroy(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_tls_destroy_handle_NULL_succeed)
{
    // arrange

    // act
    cord_tls_destroy(NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_tls_open_handle_NULL_fail)
{
    // arrange

    // act
    int result = cord_tls_open(NULL, test_on_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_tls_open_succeed)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    umock_c_reset_all_calls();

    setup_cord_tls_open_mocks();

    // act
    int result = cord_tls_open(handle, test_on_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_close(handle, NULL, NULL);
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_open_invalid_state_fail)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    int result = cord_tls_open(handle, test_on_open_complete, NULL);
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    umock_c_reset_all_calls();

    // act
    result = cord_tls_open(handle, test_on_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_close(handle, NULL, NULL);
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_open_fail)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    umock_c_reset_all_calls();

    int negativeTestsInitResult = umock_c_negative_tests_init();
    CTEST_ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    setup_cord_tls_open_mocks();

    umock_c_negative_tests_snapshot();

    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (umock_c_negative_tests_can_call_fail(index))
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            // act
            int result = cord_tls_open(handle, test_on_open_complete, NULL);

            // assert
            CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
        }
    }

    // cleanup
    cord_tls_destroy(handle);
    umock_c_negative_tests_deinit();
}

CTEST_FUNCTION(cord_tls_open_process_call_succeed)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(TLS_client_method()).CallCannotFail();
    STRICT_EXPECTED_CALL(SSL_CTX_new(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_s_mem()).CallCannotFail();
    STRICT_EXPECTED_CALL(BIO_new(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_s_mem()).CallCannotFail();
    STRICT_EXPECTED_CALL(BIO_new(IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_CTX_set_verify(IGNORED_ARG, IGNORED_ARG, NULL));
    STRICT_EXPECTED_CALL(SSL_new(IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_set_bio(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_set_connect_state(IGNORED_ARG));
    STRICT_EXPECTED_CALL(interface_socket_open(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(ERR_clear_error());
    STRICT_EXPECTED_CALL(SSL_do_handshake(IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_on_open_complete(IGNORED_ARG, IO_OPEN_OK));

    // act
    int result = cord_tls_open(handle, test_on_open_complete, NULL);
    cord_tls_process_item(handle); // Call to open
    g_on_open_complete(g_on_open_ctx, IO_OPEN_OK); // start the handshake
    cord_tls_process_item(handle); // Call to handshake

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_close(handle, NULL, NULL);
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_open_process_call_open_fail)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    (void)cord_tls_open(handle, test_on_open_complete, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(interface_socket_open(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_on_open_complete(IGNORED_ARG, IO_OPEN_ERROR));
    STRICT_EXPECTED_CALL(SSL_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_CTX_free(IGNORED_ARG));

    // act
    cord_tls_process_item(handle); // Call to open
    g_on_open_complete(g_on_open_ctx, IO_OPEN_ERROR); // start the handshake
    cord_tls_process_item(handle); // Call to open complete fail

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_close(handle, NULL, NULL);
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_close_handle_NULL_fail)
{
    // arrange

    // act
    int result = cord_tls_close(NULL, test_on_close_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_tls_close_succeed)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    (void)cord_tls_open(handle, test_on_open_complete, NULL);
    cord_tls_process_item(handle); // Call to open
    g_on_open_complete(g_on_open_ctx, IO_OPEN_OK); // start the handshake
    cord_tls_process_item(handle); // Call to handshake
    umock_c_reset_all_calls();

    //STRICT_EXPECTED_CALL(test_on_close_complete(IGNORED_ARG));
    STRICT_EXPECTED_CALL(interface_socket_close(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_CTX_free(IGNORED_ARG));

    // act
    int result = cord_tls_close(handle, test_on_close_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_close_interface_close_fail)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    (void)cord_tls_open(handle, test_on_open_complete, NULL);
    cord_tls_process_item(handle); // Call to open
    g_on_open_complete(g_on_open_ctx, IO_OPEN_OK); // start the handshake
    cord_tls_process_item(handle); // Call to handshake
    umock_c_reset_all_calls();

    //STRICT_EXPECTED_CALL(test_on_close_complete(IGNORED_ARG));
    STRICT_EXPECTED_CALL(interface_socket_close(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(__LINE__);
    STRICT_EXPECTED_CALL(SSL_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(BIO_free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(SSL_CTX_free(IGNORED_ARG));

    // act
    int result = cord_tls_close(handle, test_on_close_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_close_not_open_succeed)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    umock_c_reset_all_calls();

    // act
    int result = cord_tls_close(handle, test_on_close_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_close_process_succeed)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    (void)cord_tls_open(handle, test_on_open_complete, NULL);
    cord_tls_process_item(handle); // Call to open
    g_on_open_complete(g_on_open_ctx, IO_OPEN_OK); // start the handshake
    cord_tls_process_item(handle); // Call to handshake
    int result = cord_tls_close(handle, test_on_close_complete, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_on_close_complete(IGNORED_ARG));

    // act
    g_on_close_complete(g_on_close_ctx);
    cord_tls_process_item(handle); // Call to handshake

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_send_handle_NULL_fail)
{
    // arrange

    // act
    int result = cord_tls_send(NULL, g_send_buffer, g_buffer_len, test_on_send_complete, TEST_USER_CONTEXT_VALUE);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_tls_send_succeed)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    (void)cord_tls_open(handle, test_on_open_complete, NULL);
    cord_tls_process_item(handle); // Call to open
    g_on_open_complete(g_on_open_ctx, IO_OPEN_OK); // start the handshake
    cord_tls_process_item(handle); // Call to handshake
    umock_c_reset_all_calls();

    setup_cord_tls_send_mocks();

    // act
    int result = cord_tls_send(handle, g_send_buffer, g_buffer_len, test_on_send_complete, TEST_USER_CONTEXT_VALUE);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_tls_close(handle, NULL, NULL);
    cord_tls_destroy(handle);
}

CTEST_FUNCTION(cord_tls_send_fail)
{
    // arrange
    CORD_HANDLE handle = initialize_handle();
    (void)cord_tls_open(handle, test_on_open_complete, NULL);
    cord_tls_process_item(handle); // Call to open
    g_on_open_complete(g_on_open_ctx, IO_OPEN_OK); // start the handshake
    cord_tls_process_item(handle); // Call to handshake
    umock_c_reset_all_calls();

    int negativeTestsInitResult = umock_c_negative_tests_init();
    CTEST_ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    setup_cord_tls_send_mocks();

    umock_c_negative_tests_snapshot();

    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (umock_c_negative_tests_can_call_fail(index))
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            // act
            int result = cord_tls_send(handle, g_send_buffer, g_buffer_len, test_on_send_complete, TEST_USER_CONTEXT_VALUE);

            // assert
            CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result, "Failure in test");
        }
    }

    // cleanup
    cord_tls_close(handle, NULL, NULL);
    cord_tls_destroy(handle);
    umock_c_negative_tests_deinit();
}

CTEST_FUNCTION(cord_tls_get_tls_interface_success)
{
    // arrange

    // act
    const IO_INTERFACE_DESCRIPTION* io_desc = cord_tls_get_tls_interface();

    // assert
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_create);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_destroy);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_open);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_close);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_send);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_process_item);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_query_uri);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_query_port);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_listen);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_END_TEST_SUITE(cord_tls_openssl_ut)
