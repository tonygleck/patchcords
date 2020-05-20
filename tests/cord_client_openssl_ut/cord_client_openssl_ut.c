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

#include "patchcords/patchcord_client.h"

#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/crypto.h"
#include "openssl/opensslv.h"

MOCKABLE_FUNCTION(, void, test_on_bytes_recv, void*, context, const unsigned char*, buffer, size_t, size);
MOCKABLE_FUNCTION(, void, test_on_send_complete, void*, context, IO_SEND_RESULT, send_result);
MOCKABLE_FUNCTION(, void, test_on_open_complete, void*, context, IO_OPEN_RESULT, open_result);
MOCKABLE_FUNCTION(, void, test_on_close_complete, void*, context);
MOCKABLE_FUNCTION(, void, test_on_error, void*, context, IO_ERROR_RESULT, error_result);
MOCKABLE_FUNCTION(, void, test_on_accept_conn, void*, context, const SOCKETIO_CONFIG*, config);

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

MOCKABLE_FUNCTION(, int, X509_STORE_add_cert, X509_STORE*, ctx, X509*, x);
MOCKABLE_FUNCTION(, void, X509_free, X509*, a);

MOCKABLE_FUNCTION(, void, ERR_clear_error);
MOCKABLE_FUNCTION(, char*, ERR_error_string, unsigned long, e, char*, buf);
MOCKABLE_FUNCTION(, unsigned long, ERR_get_error);

MOCKABLE_FUNCTION(, const SSL_METHOD*, TLS_server_method);
MOCKABLE_FUNCTION(, const SSL_METHOD*, TLS_client_method);

MOCKABLE_FUNCTION(, void, SSL_CTX_free, SSL_CTX*, ctx);
MOCKABLE_FUNCTION(, X509_STORE*, SSL_CTX_get_cert_store, const SSL_CTX*, ctx);
MOCKABLE_FUNCTION(, SSL_CTX*, SSL_CTX_new, const SSL_METHOD*, meth);
MOCKABLE_FUNCTION(, void, SSL_CTX_set_verify, SSL_CTX*, ctx, int, mode, SSL_verify_cb, callback);
MOCKABLE_FUNCTION(, void, SSL_set_bio, SSL*, s, BIO*, rbio, BIO*, wbio);
MOCKABLE_FUNCTION(, void, SSL_set_connect_state, SSL*, s);
MOCKABLE_FUNCTION(, int, SSL_do_handshake, SSL*, s);
MOCKABLE_FUNCTION(, int, SSL_get_error, const SSL*, s, int, ret_code);
MOCKABLE_FUNCTION(, SSL*, SSL_new, SSL_CTX*, ctx);
MOCKABLE_FUNCTION(, int, SSL_write, SSL*, ssl, const void*, buf, int, num);
MOCKABLE_FUNCTION(, int, SSL_read, SSL*, ssl, void*, buf, int, num);

/*MOCKABLE_FUNCTION(, CORD_HANDLE, socket_create, const void*, io_create_parameters, ON_BYTES_RECEIVED, on_bytes_received, void*, on_bytes_received_ctx, ON_IO_ERROR, on_io_error, void*, on_io_error_ctx);
MOCKABLE_FUNCTION(, void, socket_destroy, CORD_HANDLE, impl_handle);
MOCKABLE_FUNCTION(, int, socket_open, CORD_HANDLE, impl_handle, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context);
MOCKABLE_FUNCTION(, int, socket_close, CORD_HANDLE, impl_handle, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, socket_send, CORD_HANDLE, impl_handle, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_ctx);
MOCKABLE_FUNCTION(, void, socket_process_item, CORD_HANDLE, impl_handle);
MOCKABLE_FUNCTION(, const char*, socket_query_uri, CORD_HANDLE, impl_handle);
MOCKABLE_FUNCTION(, uint16_t, socket_query_port, CORD_HANDLE, impl_handle);
MOCKABLE_FUNCTION(, int, socket_listen, CORD_HANDLE, impl_handle, ON_INCOMING_CONNECT, incoming_conn, void*, user_ctx);*/

#undef ENABLE_MOCKS

#include "patchcords/cord_client.h"

static const char* TEST_HOSTNAME = "test.hostname.com";
static size_t TEST_SEND_BUFFER_LEN = 16;
static uint16_t TEST_PORT_VALUE = 8543;

static void* g_item_list_user_ctx;
static const void* g_item_list[10];
static size_t g_item_list_index;
static unsigned char g_send_buffer[] = { 0x25, 0x26, 0x26, 0x28, 0x29 };
static unsigned char g_recv_buffer[] = { 0x52, 0x62, 0x88, 0x52, 0x59 };
static size_t g_buffer_len = 10;
static void* TEST_USER_CONTEXT_VALUE = (void*)0x08765432;

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

    static CORD_HANDLE socket_create(const void* xio_create_parameters, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
    {
        (void)xio_create_parameters;
        (void)on_bytes_received;
        (void)on_bytes_received_context;
        (void)on_io_error;
        (void)on_io_error_context;
        return (CORD_HANDLE)my_mem_shim_malloc(1);
    }

    static void socket_destroy(CORD_HANDLE handle)
    {
        my_mem_shim_free(handle);
    }

    static int socket_open(CORD_HANDLE impl_handle, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context)
    {
        (void)impl_handle;
        (void)on_io_open_complete;
        (void)on_io_open_complete_context;
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
#ifdef __cplusplus
}
#endif

const IO_INTERFACE_DESCRIPTION io_interface_description =
{
    socket_create,
    socket_destroy,
    socket_open,
    socket_close,
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

CTEST_BEGIN_TEST_SUITE(cord_client_openssl_ut)

CTEST_SUITE_INITIALIZE()
{
    umock_c_init(on_umock_c_error);

    REGISTER_UMOCK_ALIAS_TYPE(CORD_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(IO_OPEN_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_SEND_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_ERROR_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(ssize_t, long);
    REGISTER_UMOCK_ALIAS_TYPE(PATCH_INSTANCE_HANDLE, void*);

    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_malloc, my_mem_shim_malloc);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mem_shim_malloc, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_free, my_mem_shim_free);

    REGISTER_GLOBAL_MOCK_HOOK(clone_string, my_clone_string);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(clone_string, __LINE__);

    //REGISTER_GLOBAL_MOCK_RETURN(xio_cord_get_interface, io_interface_description);
    //REGISTER_GLOBAL_MOCK_FAIL_RETURN(xio_cord_get_interface, NULL);
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
}

CTEST_FUNCTION_CLEANUP()
{
}

static void setup_cord_client_create_mocks(void)
{
    STRICT_EXPECTED_CALL(ERR_load_BIO_strings()).CallCannotFail();
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    //STRICT_EXPECTED_CALL(xio_cord_get_interface());
    //STRICT_EXPECTED_CALL(socket_create(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(clone_string(IGNORED_ARG, IGNORED_ARG));
}

CTEST_FUNCTION(cord_client_create_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    setup_cord_client_create_mocks();

    // act
    CORD_HANDLE handle = cord_client_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);

    // assert
    CTEST_ASSERT_IS_NOT_NULL(handle);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_client_destroy(handle);
}

CTEST_FUNCTION(xio_cord_get_interface_success)
{
    // arrange

    // act
    const IO_INTERFACE_DESCRIPTION* io_desc = xio_cord_get_interface();

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

CTEST_END_TEST_SUITE(cord_client_openssl_ut)