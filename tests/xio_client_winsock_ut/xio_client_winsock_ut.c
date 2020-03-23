// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#else
#include <stdlib.h>
#include <stddef.h>
#endif

#include <errno.h>
#include "testrunnerswitcher.h"
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
#include "patchcords/xio_client.h"
#include "patchcords/socket_debug_shim.h"
#include "umock_c/umock_c_prod.h"
#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/item_list.h"
#include "lib-util-c/crt_extensions.h"

MOCKABLE_FUNCTION(, void, test_on_bytes_recv, void*, context, const unsigned char*, buffer, size_t, size);
MOCKABLE_FUNCTION(, void, test_on_send_complete, void*, context, IO_SEND_RESULT, send_result);
MOCKABLE_FUNCTION(, void, test_on_open_complete, void*, context, IO_OPEN_RESULT, open_result);
MOCKABLE_FUNCTION(, void, test_on_close_complete, void*, context);
MOCKABLE_FUNCTION(, void, test_on_error, void*, context, IO_ERROR_RESULT, error_result);

#ifdef __cplusplus
extern "C"
{
#endif
    int socket_shim_fcntl(int __fd, int __cmd, ...);
#ifdef __cplusplus
}
#endif

#undef ENABLE_MOCKS

#include "patchcords/xio_socket.h"

static const char* TEST_HOSTNAME = "test.hostname.com";
static size_t TEST_SEND_BUFFER_LEN = 16;
static uint16_t TEST_PORT_VALUE = 8543;

static ITEM_LIST_DESTROY_ITEM g_item_list_destroy_cb;
static void* g_item_list_user_ctx;
static const void* g_item_list[10];
static size_t g_item_list_index;
static int* g_socket;
static struct addrinfo g_addr_info = {0};
static struct sockaddr g_connect_addr = {0};
static unsigned char g_send_buffer[] = { 0x25, 0x26, 0x26, 0x28, 0x29 };
static unsigned char g_recv_buffer[] = { 0x52, 0x62, 0x88, 0x52, 0x59 };
static size_t g_buffer_len = 10;

#ifdef __cplusplus
extern "C" {
#endif
    int socket_shim_fcntl(int __fd, int __cmd, ...)
    {
        return 0;
    }

    static void my_item_list_destroy(ITEM_LIST_HANDLE handle)
    {
        for (size_t index = 0; index < g_item_list_index; index++)
        {
            g_item_list_destroy_cb(g_item_list_user_ctx, (void*)g_item_list[index]);
        }
        g_item_list_index = 0;
        my_mem_shim_free(handle);
    }

    static ITEM_LIST_HANDLE my_item_list_create(ITEM_LIST_DESTROY_ITEM destroy_cb, void* user_ctx)
    {
        g_item_list_destroy_cb = destroy_cb;
        g_item_list_user_ctx = user_ctx;
        return (ITEM_LIST_HANDLE)my_mem_shim_malloc(1);
    }

    static int my_item_list_add_item(ITEM_LIST_HANDLE handle, const void* item)
    {
        (void)handle;
        g_item_list[g_item_list_index++] = item;
        return 0;
    }

    static int my_item_list_remove_item(ITEM_LIST_HANDLE handle, size_t remove_index)
    {
        g_item_list_destroy_cb(g_item_list_user_ctx, (void*)g_item_list[g_item_list_index--]);
    }

    static const void* my_item_list_get_front(ITEM_LIST_HANDLE handle)
    {
        const void* result;
        if (g_item_list_index > 0)
        {
            result = g_item_list[0];
        }
        else
        {
            result = NULL;
        }
        return result;
    }

    static int my_socket_shim_socket(int domain, int type, int protocol)
    {
        g_socket = my_mem_shim_malloc(1);
        return (int)__LINE__;
    }

    static int my_socket_shim_close(int sock)
    {
        my_mem_shim_free(g_socket);
    }

    static int my_socket_shim_getaddrinfo(const char* node, const char* svc_name, const struct addrinfo* hints, struct addrinfo** res)
    {
        (void)node;
        (void)svc_name;
        (void)hints;
        (void)res;
        g_addr_info.ai_addr = &g_connect_addr;
        *res = &g_addr_info;
        return 0;
    }

    static ssize_t my_socket_shim_send(int sock, const void* buf, size_t len, int flags)
    {
        return len;
    }

    static ssize_t my_socket_shim_recv(int sock, void* buf, size_t len, int flags)
    {
        (void)sock;
        (void)buf;
        (void)len;
        (void)flags;
        errno = EAGAIN;
        return -1;
    }

    static int my_clone_string(char** target, const char* source)
    {
        size_t len = strlen(source);
        *target = my_mem_shim_malloc(len+1);
        strcpy(*target, source);
        return 0;
    }
#ifdef __cplusplus
}
#endif

TEST_DEFINE_ENUM_TYPE(IO_OPEN_RESULT, IO_OPEN_RESULT_VALUES);
IMPLEMENT_UMOCK_C_ENUM_TYPE(IO_OPEN_RESULT, IO_OPEN_RESULT_VALUES);

static TEST_MUTEX_HANDLE test_serialize_mutex;

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

BEGIN_TEST_SUITE(xio_client_winsock_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    REGISTER_UMOCK_ALIAS_TYPE(XIO_IMPL_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ITEM_LIST_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ITEM_LIST_DESTROY_ITEM, void*);
    REGISTER_UMOCK_ALIAS_TYPE(socklen_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_OPEN_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_SEND_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_ERROR_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(ssize_t, unsigned int);

    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_malloc, my_mem_shim_malloc);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mem_shim_malloc, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_free, my_mem_shim_free);

    REGISTER_GLOBAL_MOCK_HOOK(item_list_create, my_item_list_create);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(item_list_create, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(item_list_destroy, my_item_list_destroy);
    REGISTER_GLOBAL_MOCK_HOOK(item_list_add_item, my_item_list_add_item);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(item_list_add_item, __LINE__);
    REGISTER_GLOBAL_MOCK_HOOK(item_list_remove_item, my_item_list_remove_item);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(item_list_remove_item, __LINE__);
    REGISTER_GLOBAL_MOCK_HOOK(item_list_get_front, my_item_list_get_front);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(item_list_get_front, NULL);

    REGISTER_GLOBAL_MOCK_HOOK(socket_shim_socket, my_socket_shim_socket);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(socket_shim_socket, -1);
    REGISTER_GLOBAL_MOCK_HOOK(socket_shim_close, my_socket_shim_close);
    REGISTER_GLOBAL_MOCK_HOOK(socket_shim_getaddrinfo, my_socket_shim_getaddrinfo);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(socket_shim_getaddrinfo, __LINE__);
    REGISTER_GLOBAL_MOCK_HOOK(socket_shim_send, my_socket_shim_send);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(socket_shim_send, -1);
    REGISTER_GLOBAL_MOCK_HOOK(socket_shim_recv, my_socket_shim_recv);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(socket_shim_recv, 0);

    REGISTER_GLOBAL_MOCK_HOOK(clone_string, my_clone_string);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(clone_string, __LINE__);
}

TEST_SUITE_CLEANUP(suite_cleanup)
{
    umock_c_deinit();
    TEST_MUTEX_DESTROY(test_serialize_mutex);
}

TEST_FUNCTION_INITIALIZE(method_init)
{
    if (TEST_MUTEX_ACQUIRE(g_testByTest))
    {
        ASSERT_FAIL("Could not acquire test serialization mutex.");
    }
    umock_c_reset_all_calls();

    g_item_list_destroy_cb = NULL;
    g_item_list_user_ctx = NULL;
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    TEST_MUTEX_RELEASE(g_testByTest);
}

static void setup_xio_socket_create_mocks(void)
{
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(item_list_create(IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(clone_string(IGNORED_ARG, IGNORED_ARG));
}

static void setup_xio_socket_process_item_open_mocks(void)
{
    STRICT_EXPECTED_CALL(getaddrinfo(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(connect(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_on_open_complete(IGNORED_ARG, IO_OPEN_OK));
    STRICT_EXPECTED_CALL(socket_shim_freeaddrinfo(IGNORED_ARG));
}

TEST_FUNCTION(xio_socket_create_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    setup_xio_socket_create_mocks();

    // act
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);

    // assert
    ASSERT_IS_NOT_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_create_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    int negativeTestsInitResult = umock_c_negative_tests_init();
    ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);
    umock_c_reset_all_calls();

    setup_xio_socket_create_mocks();

    umock_c_negative_tests_snapshot();

    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (umock_c_negative_tests_can_call_fail(index))
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            // act
            XIO_IMPL_HANDLE handle = xio_socket_create(&config);

            // assert
            ASSERT_IS_NULL(handle, "xio_socket_create failure %zu/%zu", index, count);
        }
    }
    // cleanup
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(xio_socket_create_config_NULL_fail)
{
    // arrange

    // act
    XIO_IMPL_HANDLE handle = xio_socket_create(NULL);

    // assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_socket_destroy_handle_NULL_succeed)
{
    // arrange

    // act
    xio_socket_destroy(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_socket_destroy_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(item_list_destroy(IGNORED_ARG));
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    // act
    xio_socket_destroy(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_socket_open_xio_NULL_fail)
{
    // arrange

    // act
    int result = xio_socket_open(NULL, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_socket_open_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(socket(AF_INET, SOCK_STREAM, 0)).SetReturn(-1);

    // act
    int result = xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_socket_destroy(handle);
}


TEST_FUNCTION(xio_socket_open_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(socket(AF_INET, SOCK_STREAM, 0));
    setup_xio_socket_process_item_open_mocks();

    // act
    int result = xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    xio_socket_process_item(handle);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    my_mem_shim_free(g_socket);
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_open_UDP_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_UDP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));

    // act
    int result = xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    my_mem_shim_free(g_socket);
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_open_call_when_open_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    int result = xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    // act
    result = xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    my_mem_shim_free(g_socket);
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_close_xio_NULL_Fail)
{
    // arrange

    // act
    int result = xio_socket_close(NULL, test_on_close_complete, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_socket_close_not_open_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    umock_c_reset_all_calls();

    // act
    int result = xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_close_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(shutdown(IGNORED_ARG, SHUT_RDWR));
    STRICT_EXPECTED_CALL(close(IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_on_close_complete(IGNORED_ARG));

    // act
    int result = xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_send_xio_NULL_fail)
{
    // arrange

    // act
    int result = xio_socket_send(NULL, g_send_buffer, g_buffer_len, test_on_send_complete, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_socket_send_not_open_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    umock_c_reset_all_calls();

    // act
    int result = xio_socket_send(handle, g_send_buffer, g_buffer_len, test_on_send_complete, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_send_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    xio_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(send(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, 0));//.SetReturn(g_buffer_len);
    STRICT_EXPECTED_CALL(test_on_send_complete(IGNORED_ARG, IO_SEND_OK));
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    // act
    int result = xio_socket_send(handle, g_send_buffer, g_buffer_len, test_on_send_complete, NULL);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_send_no_callback_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    xio_socket_process_item(handle);
    umock_c_reset_all_calls();

    /*STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(send(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(g_buffer_len);
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    // act
    int result = xio_socket_send(handle, g_send_buffer, g_buffer_len, NULL, NULL);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());*/

    // cleanup
    (void)xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);
    xio_socket_destroy(handle);
}

/*TEST_FUNCTION(xio_socket_send_partial_send_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    xio_socket_process_item(handle);
    umock_c_reset_all_calls();

    size_t partial_send_len = g_buffer_len/2;
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(send(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(partial_send_len);
    STRICT_EXPECTED_CALL(item_list_add_item(IGNORED_ARG, IGNORED_ARG));

    // act
    int result = xio_socket_send(handle, g_send_buffer, g_buffer_len, test_on_send_complete, NULL);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);
    xio_socket_destroy(handle);
}*/

TEST_FUNCTION(xio_socket_process_item_handle_NULL_success)
{
    // arrange

    // act
    xio_socket_process_item(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_socket_process_item_open_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    setup_xio_socket_process_item_open_mocks();

    // act
    xio_socket_process_item(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_process_item_getaddrinfo_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(getaddrinfo(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(__LINE__);
    STRICT_EXPECTED_CALL(test_on_open_complete(IGNORED_ARG, IO_OPEN_ERROR));

    // act
    xio_socket_process_item(handle);

    // assert

    // cleanup
    xio_socket_close(handle, NULL, NULL);
    xio_socket_process_item(handle);
    xio_socket_destroy(handle);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(xio_socket_process_item_connect_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(getaddrinfo(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(connect(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(1);
    STRICT_EXPECTED_CALL(test_on_open_complete(IGNORED_ARG, IO_OPEN_ERROR));
    STRICT_EXPECTED_CALL(socket_shim_freeaddrinfo(IGNORED_ARG));

    // act
    xio_socket_process_item(handle);

    // assert

    // cleanup
    xio_socket_close(handle, NULL, NULL);
    xio_socket_process_item(handle);

    xio_socket_destroy(handle);
    umock_c_negative_tests_deinit();
}

TEST_FUNCTION(xio_socket_process_item_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    xio_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(item_list_get_front(IGNORED_ARG));
    STRICT_EXPECTED_CALL(recv(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));

    // act
    xio_socket_process_item(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_process_item_recv_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    xio_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(item_list_get_front(IGNORED_ARG));
    STRICT_EXPECTED_CALL(recv(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(g_buffer_len);
        /*.CopyOutArgumentBuffer_buf(g_recv_buffer, sizeof(g_recv_buffer))
        .CopyOutArgumentBuffer_len(&g_buffer_len, sizeof(g_buffer_len));*/
    STRICT_EXPECTED_CALL(test_on_bytes_recv(IGNORED_ARG, IGNORED_ARG, g_buffer_len));

    // act
    xio_socket_process_item(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);
    xio_socket_destroy(handle);
}

/*TEST_FUNCTION(xio_socket_process_item_recv_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    xio_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(item_list_get_front(IGNORED_ARG));
    STRICT_EXPECTED_CALL(recv(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(0);
    STRICT_EXPECTED_CALL(test_on_error(IGNORED_ARG, IO_ERROR_SERVER_DISCONN));

    // act
    xio_socket_process_item(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_process_item_recv_general_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    (void)xio_socket_open(handle, test_on_open_complete, NULL, test_on_bytes_recv, NULL, test_on_error, NULL);
    xio_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(item_list_get_front(IGNORED_ARG));
    STRICT_EXPECTED_CALL(recv(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(-1);
    STRICT_EXPECTED_CALL(test_on_error(IGNORED_ARG, IO_ERROR_GENERAL));

    // act
    errno = ENOEXEC;
    xio_socket_process_item(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)xio_socket_close(handle, test_on_close_complete, NULL);
    xio_socket_process_item(handle);
    xio_socket_destroy(handle);
}*/

TEST_FUNCTION(xio_socket_query_endpoint_NULL_fail)
{
    // arrange

    // act
    xio_socket_query_uri(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_socket_query_endpoint_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    umock_c_reset_all_calls();

    // act
    const char* endpoint = xio_socket_query_uri(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, TEST_HOSTNAME, endpoint);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_query_port_handle_NULL_fail)
{
    // arrange

    // act
    uint16_t port = xio_socket_query_port(NULL);

    // assert
    ASSERT_ARE_EQUAL(uint16_t, 0, port);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_socket_query_port_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    XIO_IMPL_HANDLE handle = xio_socket_create(&config);
    umock_c_reset_all_calls();

    // act
    uint16_t port = xio_socket_query_port(handle);

    // assert
    ASSERT_ARE_EQUAL(uint16_t, TEST_PORT_VALUE, port);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_socket_destroy(handle);
}

TEST_FUNCTION(xio_socket_get_interface_success)
{
    // arrange

    // act
    const IO_INTERFACE_DESCRIPTION* io_desc = xio_socket_get_interface();

    // assert
    ASSERT_IS_NOT_NULL(io_desc->interface_impl_create);
    ASSERT_IS_NOT_NULL(io_desc->interface_impl_destroy);
    ASSERT_IS_NOT_NULL(io_desc->interface_impl_open);
    ASSERT_IS_NOT_NULL(io_desc->interface_impl_close);
    ASSERT_IS_NOT_NULL(io_desc->interface_impl_send);
    ASSERT_IS_NOT_NULL(io_desc->interface_impl_process_item);
    ASSERT_IS_NOT_NULL(io_desc->interface_impl_query_uri);
    ASSERT_IS_NOT_NULL(io_desc->interface_impl_query_port);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

END_TEST_SUITE(xio_client_winsock_ut)
