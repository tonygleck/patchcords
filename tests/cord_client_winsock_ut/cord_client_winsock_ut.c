// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#else
#include <stdlib.h>
#include <stddef.h>
#endif

static void* my_mem_shim_malloc(size_t size)
{
    return malloc(size);
}

static void my_mem_shim_free(void* ptr)
{
    free(ptr);
}

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "ctest.h"
#include "azure_macro_utils/macro_utils.h"
#include "umock_c/umock_c.h"

#include "umock_c/umock_c_negative_tests.h"
#include "umock_c/umocktypes_charptr.h"

#define ENABLE_MOCKS
#include "patchcords/patchcord_client.h"
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

#include "patchcords/cord_socket_client.h"

static const char* TEST_HOSTNAME = "test.hostname.com";
static const char* TEST_PORT_STRING = "8543";
static uint16_t TEST_PORT_VALUE = 8543;
static size_t TEST_SEND_BUFFER_LEN = 16;

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

static ADDRINFO TEST_ADDR_INFO = { 0 };
#define FAKE_GOOD_IP_ADDR 444

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
        return 0;
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

    static SOCKET my_socket_shim_socket(int domain, int type, int protocol)
    {
        g_socket = my_mem_shim_malloc(1);
        return (int)__LINE__;
    }

    static int my_socket_shim_close(SOCKET sock)
    {
        my_mem_shim_free(g_socket);
        return 0;
    }

    static int my_socket_shim_getaddrinfo(const char* node, const char* svc_name, const struct addrinfo* hints, struct addrinfo** res)
    {
        (void)node;
        (void)svc_name;
        (void)hints;
        //g_addr_info.ai_addr = &g_connect_addr;
        *res = (PADDRINFOA)my_mem_shim_malloc(sizeof(ADDRINFOA));
        memcpy(*res, &TEST_ADDR_INFO, sizeof(ADDRINFOA));
        return 0;
    }

    static void my_socket_shim_freeaddrinfo(PADDRINFOA result)
    {
        my_mem_shim_free(result);
    }

    static int my_socket_shim_send(SOCKET sock, const void* buf, int len, int flags)
    {
        return len;
    }

    static int my_socket_shim_recv(SOCKET sock, void* buf, int len, int flags)
    {
        (void)sock;
        (void)buf;
        (void)len;
        (void)flags;
        return -1;
    }

    static int my_clone_string(char** target, const char* source)
    {
        size_t len = strlen(source);
        *target = my_mem_shim_malloc(len+1);
        strcpy(*target, source);
        return 0;
    }

    char* umocktypes_stringify_const_ADDRINFOA_ptr(const ADDRINFOA** value)
    {
        char* result = NULL;
        char temp_buffer[256];
        int length;

        length = sprintf(temp_buffer, "{ ai_flags = %d, ai_family = %d, ai_socktype = %d, ai_protocol = %d, ai_addrlen = %u, ai_canonname = %s", (*value)->ai_flags, (*value)->ai_family, (*value)->ai_socktype, (*value)->ai_protocol, (unsigned int)((*value)->ai_addrlen), (*value)->ai_canonname);
        if (length > 0)
        {
            result = (char*)my_mem_shim_malloc(strlen(temp_buffer) + 1);
            if (result != NULL)
            {
                (void)memcpy(result, temp_buffer, strlen(temp_buffer) + 1);
            }
        }

        return result;
    }

    int umocktypes_are_equal_const_ADDRINFOA_ptr(const ADDRINFOA** left, const ADDRINFOA** right)
    {
        int result = 1;
        if (((*left)->ai_flags != (*right)->ai_flags) ||
            ((*left)->ai_family != (*right)->ai_family) ||
            ((*left)->ai_socktype != (*right)->ai_socktype) ||
            ((*left)->ai_protocol != (*right)->ai_protocol) ||
            ((((*left)->ai_canonname == NULL) || ((*right)->ai_canonname == NULL)) && ((*left)->ai_canonname != (*right)->ai_canonname)) ||
            (((*left)->ai_canonname != NULL && (*right)->ai_canonname != NULL) && (strcmp((*left)->ai_canonname, (*right)->ai_canonname) != 0)))
        {
            result = 0;
        }
        return result;
    }

    int umocktypes_copy_const_ADDRINFOA_ptr(ADDRINFOA** destination, const ADDRINFOA** source)
    {
        int result;
        *destination = (ADDRINFOA*)my_mem_shim_malloc(sizeof(ADDRINFOA));
        if (*destination == NULL)
        {
            result = __LINE__;
        }
        else
        {
            (*destination)->ai_flags = (*source)->ai_flags;
            (*destination)->ai_family = (*source)->ai_family;
            (*destination)->ai_socktype = (*source)->ai_socktype;
            (*destination)->ai_protocol = (*source)->ai_protocol;
            (*destination)->ai_canonname = (*source)->ai_canonname;
            result = 0;
        }

        return result;
    }

    void umocktypes_free_const_ADDRINFOA_ptr(ADDRINFOA** value)
    {
        my_mem_shim_free(*value);
    }

    char* umocktypes_stringify_const_struct_sockaddr_ptr(const struct sockaddr** value)
    {
        char* result = NULL;
        char temp_buffer[256];
        int length;

        length = sprintf(temp_buffer, "{ sa_family = %u, sa_data = ... }", (unsigned int)((*value)->sa_family));
        if (length > 0)
        {
            result = (char*)my_mem_shim_malloc(strlen(temp_buffer) + 1);
            if (result != NULL)
            {
                (void)memcpy(result, temp_buffer, strlen(temp_buffer) + 1);
            }
        }

        return result;
    }

    int umocktypes_are_equal_const_struct_sockaddr_ptr(const struct sockaddr** left, const struct sockaddr** right)
    {
        int result = 1;
        if (((*left)->sa_family != (*left)->sa_family) ||
            (memcmp((*left)->sa_data, (*right)->sa_data, sizeof((*left)->sa_data) != 0)))
        {
            result = 0;
        }

        return result;
    }

    int umocktypes_copy_const_struct_sockaddr_ptr(struct sockaddr** destination, const struct sockaddr** source)
    {
        int result;

        *destination = (struct sockaddr*)my_mem_shim_malloc(sizeof(struct sockaddr));
        if (*destination == NULL)
        {
            result = MU_FAILURE;
        }
        else
        {
            (*destination)->sa_family = (*source)->sa_family;
            (void)memcpy((*destination)->sa_data, (*source)->sa_data, sizeof((*source)->sa_data));

            result = 0;
        }

        return result;
    }

    void umocktypes_free_const_struct_sockaddr_ptr(struct sockaddr** value)
    {
        my_mem_shim_free(*value);
    }

#ifdef __cplusplus
}
#endif

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    CTEST_ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

CTEST_BEGIN_TEST_SUITE(cord_socket_winsock_ut)

CTEST_SUITE_INITIALIZE()
{
    umock_c_init(on_umock_c_error);

    CTEST_ASSERT_ARE_EQUAL(int, 0, umocktypes_charptr_register_types());

    REGISTER_UMOCK_ALIAS_TYPE(CORD_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ITEM_LIST_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ITEM_LIST_DESTROY_ITEM, void*);
    REGISTER_UMOCK_ALIAS_TYPE(socklen_t, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_OPEN_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_SEND_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(IO_ERROR_RESULT, int);
    REGISTER_UMOCK_ALIAS_TYPE(DWORD, unsigned long);
    REGISTER_UMOCK_ALIAS_TYPE(LPVOID, void*);
    REGISTER_UMOCK_ALIAS_TYPE(LPDWORD, void*);
    REGISTER_UMOCK_ALIAS_TYPE(WORD, unsigned short);
    REGISTER_UMOCK_ALIAS_TYPE(SOCKET, void*);
    REGISTER_UMOCK_ALIAS_TYPE(PCSTR, char*);
    REGISTER_UMOCK_ALIAS_TYPE(LPWSADATA, void*);
    REGISTER_TYPE(const ADDRINFOA*, const_ADDRINFOA_ptr);
    REGISTER_UMOCK_ALIAS_TYPE(PADDRINFOA, const ADDRINFOA*);

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
    REGISTER_GLOBAL_MOCK_HOOK(socket_shim_freeaddrinfo, my_socket_shim_freeaddrinfo);
    REGISTER_GLOBAL_MOCK_HOOK(socket_shim_send, my_socket_shim_send);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(socket_shim_send, -1);
    REGISTER_GLOBAL_MOCK_HOOK(socket_shim_recv, my_socket_shim_recv);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(socket_shim_recv, 0);

    REGISTER_GLOBAL_MOCK_HOOK(clone_string, my_clone_string);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(clone_string, __LINE__);

    REGISTER_GLOBAL_MOCK_RETURN(WSAStartup, 0);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(WSAStartup, 1);

    TEST_ADDR_INFO.ai_next = NULL;
    TEST_ADDR_INFO.ai_family = AF_INET;
    TEST_ADDR_INFO.ai_socktype = SOCK_STREAM;
    TEST_ADDR_INFO.ai_addr = (struct sockaddr*)(&g_connect_addr);
    ((struct sockaddr_in*)TEST_ADDR_INFO.ai_addr)->sin_addr.s_addr = FAKE_GOOD_IP_ADDR;
}

CTEST_SUITE_CLEANUP()
{
    umock_c_deinit();
}

CTEST_FUNCTION_INITIALIZE()
{
    umock_c_reset_all_calls();

    g_item_list_destroy_cb = NULL;
    g_item_list_user_ctx = NULL;
}

CTEST_FUNCTION_CLEANUP()
{
}

static void setup_cord_socket_create_mocks(void)
{
    STRICT_EXPECTED_CALL(WSAStartup(IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(item_list_create(IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(clone_string(IGNORED_ARG, IGNORED_ARG));
}

static void setup_cord_socket_process_item_open_mocks(void)
{
    STRICT_EXPECTED_CALL(getaddrinfo(TEST_HOSTNAME, TEST_PORT_STRING, &TEST_ADDR_INFO, IGNORED_ARG));
    STRICT_EXPECTED_CALL(connect(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(ioctlsocket(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_on_open_complete(IGNORED_ARG, IO_OPEN_OK));
    STRICT_EXPECTED_CALL(socket_shim_freeaddrinfo(IGNORED_ARG));
}

CTEST_FUNCTION(cord_socket_create_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    setup_cord_socket_create_mocks();

    // act
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);

    // assert
    CTEST_ASSERT_IS_NOT_NULL(handle);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_create_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    int negativeTestsInitResult = umock_c_negative_tests_init();
    CTEST_ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);
    umock_c_reset_all_calls();

    setup_cord_socket_create_mocks();

    umock_c_negative_tests_snapshot();

    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        if (umock_c_negative_tests_can_call_fail(index))
        {
            umock_c_negative_tests_reset();
            umock_c_negative_tests_fail_call(index);

            // act
            CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);

            // assert
            CTEST_ASSERT_IS_NULL(handle, "cord_socket_create failure %zu/%zu", index, count);
        }
    }
    // cleanup
    umock_c_negative_tests_deinit();
}

CTEST_FUNCTION(cord_socket_create_config_NULL_fail)
{
    // arrange

    // act
    CORD_HANDLE handle = cord_socket_create(NULL, test_on_bytes_recv, NULL, test_on_error, NULL);

    // assert
    CTEST_ASSERT_IS_NULL(handle);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_socket_destroy_handle_NULL_succeed)
{
    // arrange

    // act
    cord_socket_destroy(NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_socket_destroy_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(item_list_destroy(IGNORED_ARG));
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));
    STRICT_EXPECTED_CALL(WSACleanup());

    // act
    cord_socket_destroy(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_socket_open_xio_NULL_fail)
{
    // arrange

    // act
    int result = cord_socket_open(NULL, test_on_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_socket_open_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(socket(AF_INET, SOCK_STREAM, 0)).SetReturn(-1);

    // act
    int result = cord_socket_open(handle, test_on_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_open_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(socket(AF_INET, SOCK_STREAM, 0));
    setup_cord_socket_process_item_open_mocks();

    // act
    int result = cord_socket_open(handle, test_on_open_complete, NULL);
    cord_socket_process_item(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    my_mem_shim_free(g_socket);
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_open_UDP_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_UDP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP));

    // act
    int result = cord_socket_open(handle, test_on_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    my_mem_shim_free(g_socket);
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_open_call_when_open_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    int result = cord_socket_open(handle, test_on_open_complete, NULL);
    umock_c_reset_all_calls();

    // act
    result = cord_socket_open(handle, test_on_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    my_mem_shim_free(g_socket);
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_close_xio_NULL_Fail)
{
    // arrange

    // act
    int result = cord_socket_close(NULL, test_on_close_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_socket_close_not_open_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    // act
    int result = cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_close_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(shutdown(IGNORED_ARG, SD_BOTH));
    STRICT_EXPECTED_CALL(closesocket(IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_on_close_complete(IGNORED_ARG));

    // act
    int result = cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_send_xio_NULL_fail)
{
    // arrange

    // act
    int result = cord_socket_send(NULL, g_send_buffer, g_buffer_len, test_on_send_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_socket_send_not_open_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    // act
    int result = cord_socket_send(handle, g_send_buffer, g_buffer_len, test_on_send_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_send_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    cord_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(send(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, 0));//.SetReturn(g_buffer_len);
    STRICT_EXPECTED_CALL(test_on_send_complete(IGNORED_ARG, IO_SEND_OK));
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    // act
    int result = cord_socket_send(handle, g_send_buffer, g_buffer_len, test_on_send_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_send_no_callback_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    cord_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(send(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn((int)g_buffer_len);
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    // act
    int result = cord_socket_send(handle, g_send_buffer, g_buffer_len, NULL, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);
    cord_socket_destroy(handle);
}

#if 0
CTEST_FUNCTION(cord_socket_send_partial_send_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    cord_socket_process_item(handle);
    umock_c_reset_all_calls();

    size_t partial_send_len = g_buffer_len/2;
    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(send(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(partial_send_len);
    STRICT_EXPECTED_CALL(item_list_add_item(IGNORED_ARG, IGNORED_ARG));

    // act
    int result = cord_socket_send(handle, g_send_buffer, g_buffer_len, test_on_send_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);
    cord_socket_destroy(handle);
}

/*CTEST_FUNCTION(cord_socket_process_item_handle_NULL_success)
{
    // arrange

    // act
    cord_socket_process_item(NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_socket_process_item_open_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    umock_c_reset_all_calls();

    setup_cord_socket_process_item_open_mocks();

    // act
    cord_socket_process_item(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_process_item_getaddrinfo_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(getaddrinfo(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(__LINE__);
    STRICT_EXPECTED_CALL(test_on_open_complete(IGNORED_ARG, IO_OPEN_ERROR));

    // act
    cord_socket_process_item(handle);

    // assert

    // cleanup
    cord_socket_close(handle, NULL, NULL);
    cord_socket_process_item(handle);
    cord_socket_destroy(handle);
    umock_c_negative_tests_deinit();
}

CTEST_FUNCTION(cord_socket_process_item_connect_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(getaddrinfo(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));
    STRICT_EXPECTED_CALL(connect(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(1);
    STRICT_EXPECTED_CALL(test_on_open_complete(IGNORED_ARG, IO_OPEN_ERROR));
    STRICT_EXPECTED_CALL(socket_shim_freeaddrinfo(IGNORED_ARG));

    // act
    cord_socket_process_item(handle);

    // assert

    // cleanup
    cord_socket_close(handle, NULL, NULL);
    cord_socket_process_item(handle);

    cord_socket_destroy(handle);
    umock_c_negative_tests_deinit();
}

CTEST_FUNCTION(cord_socket_process_item_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    cord_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(item_list_get_front(IGNORED_ARG));
    STRICT_EXPECTED_CALL(recv(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));

    // act
    cord_socket_process_item(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_process_item_recv_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    cord_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(item_list_get_front(IGNORED_ARG));
    STRICT_EXPECTED_CALL(recv(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(g_buffer_len);
        /*.CopyOutArgumentBuffer_buf(g_recv_buffer, sizeof(g_recv_buffer))
        .CopyOutArgumentBuffer_len(&g_buffer_len, sizeof(g_buffer_len));*/
    STRICT_EXPECTED_CALL(test_on_bytes_recv(IGNORED_ARG, IGNORED_ARG, g_buffer_len));

    // act
    cord_socket_process_item(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);
    cord_socket_destroy(handle);
}

/*CTEST_FUNCTION(cord_socket_process_item_recv_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    cord_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(item_list_get_front(IGNORED_ARG));
    STRICT_EXPECTED_CALL(recv(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(0);
    STRICT_EXPECTED_CALL(test_on_error(IGNORED_ARG, IO_ENDPOINT_DISCONNECTED));

    // act
    cord_socket_process_item(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_process_item_recv_general_fail)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    (void)cord_socket_open(handle, test_on_open_complete, NULL);
    cord_socket_process_item(handle);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(item_list_get_front(IGNORED_ARG));
    STRICT_EXPECTED_CALL(recv(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG, IGNORED_ARG)).SetReturn(-1);
    STRICT_EXPECTED_CALL(test_on_error(IGNORED_ARG, IO_ERROR_GENERAL));

    // act
    errno = ENOEXEC;
    cord_socket_process_item(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    (void)cord_socket_close(handle, test_on_close_complete, NULL);
    cord_socket_process_item(handle);
    cord_socket_destroy(handle);
}*/

/*CTEST_FUNCTION(cord_socket_query_endpoint_NULL_fail)
{
    // arrange

    // act
    cord_socket_query_uri(NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_socket_query_endpoint_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    // act
    const char* endpoint = cord_socket_query_uri(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, TEST_HOSTNAME, endpoint);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_socket_destroy(handle);
}

CTEST_FUNCTION(cord_socket_query_port_handle_NULL_fail)
{
    // arrange

    // act
    uint16_t port = cord_socket_query_port(NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(uint16_t, 0, port);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(cord_socket_query_port_success)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;
    CORD_HANDLE handle = cord_socket_create(&config, test_on_bytes_recv, NULL, test_on_error, NULL);
    umock_c_reset_all_calls();

    // act
    uint16_t port = cord_socket_query_port(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(uint16_t, TEST_PORT_VALUE, port);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    cord_socket_destroy(handle);
}*/
#endif

CTEST_FUNCTION(cord_socket_get_interface_success)
{
    // arrange

    // act
    const IO_INTERFACE_DESCRIPTION* io_desc = cord_socket_get_interface();

    // assert
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_create);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_destroy);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_open);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_close);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_send);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_process_item);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_query_uri);
    CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_query_port);
    //CTEST_ASSERT_IS_NOT_NULL(io_desc->interface_impl_l);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_END_TEST_SUITE(cord_socket_winsock_ut)
