// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#include <cstdint>
#else
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#endif

#include "ctest.h"
#include "azure_macro_utils/macro_utils.h"
#include "umock_c/umock_c.h"
#include "umock_c/umock_c_prod.h"

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

#include "patchcords/patchcord_client.h"

#define ENABLE_MOCKS
#include "umock_c/umock_c_prod.h"
#include "lib-util-c/sys_debug_shim.h"

MOCKABLE_FUNCTION(, CORD_HANDLE, test_xio_create, const void*, xio_create_parameters, ON_BYTES_RECEIVED, on_bytes_received, void*, on_bytes_received_context, ON_IO_ERROR, on_io_error, void*, on_io_error_context);
MOCKABLE_FUNCTION(, void, test_xio_destroy, CORD_HANDLE, handle);
MOCKABLE_FUNCTION(, int, test_xio_open, CORD_HANDLE, handle, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context);
MOCKABLE_FUNCTION(, int, test_xio_close, CORD_HANDLE, handle, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, test_xio_send, CORD_HANDLE, handle, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, test_xio_process_item, CORD_HANDLE, handle);
MOCKABLE_FUNCTION(, const char*, test_xio_query_uri, CORD_HANDLE, handle);
MOCKABLE_FUNCTION(, uint16_t, test_xio_query_port, CORD_HANDLE, handle);
MOCKABLE_FUNCTION(, int, test_patchcord_client_listen, CORD_HANDLE, handle, ON_INCOMING_CONNECT, incoming_conn, void*, user_ctx);

#undef ENABLE_MOCKS

static const char* TEST_SEND_BUFFER = "Test send buffer";
static const char* TEST_ENDPOINT = "Test_Endpoint";
static size_t TEST_SEND_BUFFER_LEN = 16;

#ifdef __cplusplus
extern "C" {
#endif
    CORD_HANDLE my_test_xio_create(const void* xio_create_parameters, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
    {
        (void)xio_create_parameters;
        return (CORD_HANDLE)my_mem_shim_malloc(1);
    }

    void my_test_xio_destroy(CORD_HANDLE handle)
    {
        my_mem_shim_free(handle);
    }

    void test_on_bytes_received(void* context, const unsigned char* buffer, size_t size)
    {
        (void)context;
        (void)buffer;
        (void)size;
    }

    void test_on_io_open_complete(void* context, IO_OPEN_RESULT open_result)
    {
        (void)context;
        (void)open_result;
    }

    void test_on_io_close_complete(void* context)
    {
        (void)context;
    }

    void test_on_io_error(void* context, IO_ERROR_RESULT error_result)
    {
        (void)context;
    }

    void test_on_send_complete(void* context, IO_SEND_RESULT send_result)
    {
        (void)context;
        (void)send_result;
    }

    static void test_on_accept_conn(void* context, const SOCKETIO_CONFIG* config)
    {

    }

#ifdef __cplusplus
}
#endif

const IO_INTERFACE_DESCRIPTION io_interface_description =
{
    test_xio_create,
    test_xio_destroy,
    test_xio_open,
    test_xio_close,
    test_xio_send,
    test_xio_process_item,
    test_xio_query_uri,
    test_xio_query_port,
    test_patchcord_client_listen
};

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    CTEST_ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

CTEST_BEGIN_TEST_SUITE(patchcord_client_ut)

CTEST_SUITE_INITIALIZE()
{
    umock_c_init(on_umock_c_error);

    REGISTER_UMOCK_ALIAS_TYPE(CORD_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_OPEN_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_CLOSE_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_SEND_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_BYTES_RECEIVED, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_ERROR, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_INCOMING_CONNECT, void*);

    //REGISTER_GLOBAL_MOCK_HOOK(item_destroy_callback, my_item_destroy_cb);

    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_malloc, my_mem_shim_malloc);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mem_shim_malloc, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_free, my_mem_shim_free);

    REGISTER_GLOBAL_MOCK_HOOK(test_xio_create, my_test_xio_create);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(test_xio_create, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(test_xio_destroy, my_test_xio_destroy);

    REGISTER_GLOBAL_MOCK_RETURN(test_xio_query_uri, TEST_ENDPOINT);
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

CTEST_FUNCTION(xio_create_succeed)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;

    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_xio_create(&parameters, test_on_bytes_received, NULL, test_on_io_error, NULL));

    // act
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);

    // assert
    CTEST_ASSERT_IS_NOT_NULL(handle);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(xio_create_fail)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;

    int negativeTestsInitResult = umock_c_negative_tests_init();
    CTEST_ASSERT_ARE_EQUAL(int, 0, negativeTestsInitResult);

    STRICT_EXPECTED_CALL(malloc(IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_xio_create(&parameters, test_on_bytes_received, NULL, test_on_io_error, NULL));

    umock_c_negative_tests_snapshot();

    size_t count = umock_c_negative_tests_call_count();
    for (size_t index = 0; index < count; index++)
    {
        umock_c_negative_tests_reset();
        umock_c_negative_tests_fail_call(index);

        // act
        PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);

        // assert
        CTEST_ASSERT_IS_NULL(handle);
    }

    // cleanup
    umock_c_negative_tests_deinit();
}

CTEST_FUNCTION(xio_create_interface_desc_NULL_fail)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;

    // act
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(NULL, &parameters, &client_callbacks);

    // assert
    CTEST_ASSERT_IS_NULL(handle);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(patchcord_client_destroy_success)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;

    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_destroy(IGNORED_ARG));
    STRICT_EXPECTED_CALL(free(IGNORED_ARG));

    // act
    patchcord_client_destroy(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(patchcord_client_destroy_handle_NULL_fail)
{
    // arrange

    // act
    patchcord_client_destroy(NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(patchcord_client_open_handle_NULL_fail)
{
    // arrange

    // act
    int result = patchcord_client_open(NULL, test_on_io_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(patchcord_client_open_success)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;

    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_open(IGNORED_ARG, test_on_io_open_complete, NULL));

    // act
    int result = patchcord_client_open(handle, test_on_io_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_open_fail)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;

    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_open(IGNORED_ARG, test_on_io_open_complete, NULL)).SetReturn(__LINE__);

    // act
    int result = patchcord_client_open(handle, test_on_io_open_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_close_handle_NULL_fail)
{
    // arrange

    // act
    int result = patchcord_client_close(NULL, test_on_io_close_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(patchcord_client_close_success)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_close(IGNORED_ARG, test_on_io_close_complete, NULL));

    // act
    int result = patchcord_client_close(handle, test_on_io_close_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_close_fail)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_close(IGNORED_ARG, test_on_io_close_complete, NULL)).SetReturn(__LINE__);

    // act
    int result = patchcord_client_close(handle, test_on_io_close_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_send_handle_NULL_fail)
{
    // arrange

    // act
    int result = patchcord_client_send(NULL, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(patchcord_client_send_success)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_send(IGNORED_ARG, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL));

    // act
    int result = patchcord_client_send(handle, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_send_fail)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_send(IGNORED_ARG, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL)).SetReturn(__LINE__);

    // act
    int result = patchcord_client_send(handle, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_process_item_NULL_fail)
{
    // arrange

    // act
    patchcord_client_process_item(NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(patchcord_client_process_item_success)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_process_item(IGNORED_ARG));

    // act
    patchcord_client_process_item(handle);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_query_endpoint_NULL_fail)
{
    // arrange
    uint16_t port;

    // act
    patchcord_client_query_endpoint(NULL, &port);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_FUNCTION(patchcord_client_query_endpoint_success)
{
    // arrange
    int parameters = 10;
    uint16_t port;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_query_port(IGNORED_ARG));
    STRICT_EXPECTED_CALL(test_xio_query_uri(IGNORED_ARG));

    // act
    const char* endpoint = patchcord_client_query_endpoint(handle, &port);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, TEST_ENDPOINT, endpoint);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_query_endpoint_no_port_success)
{
    // arrange
    int parameters = 10;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_query_uri(IGNORED_ARG));

    // act
    const char* endpoint = patchcord_client_query_endpoint(handle, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(char_ptr, TEST_ENDPOINT, endpoint);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_listen_success)
{
    // arrange
    int parameters = 10;
    uint16_t port;
    PATCHCORD_CALLBACK_INFO client_callbacks = { 0 };
    client_callbacks.on_bytes_received = test_on_bytes_received;
    client_callbacks.on_io_error = test_on_io_error;
    PATCH_INSTANCE_HANDLE handle = patchcord_client_create(&io_interface_description, &parameters, &client_callbacks);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_patchcord_client_listen(IGNORED_ARG, IGNORED_ARG, IGNORED_ARG));

    // act
    int result = patchcord_client_listen(handle, test_on_accept_conn, NULL);

    // assert
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    patchcord_client_destroy(handle);
}

CTEST_FUNCTION(patchcord_client_listen_handle_NULL_fail)
{
    // arrange

    // act
    int result = patchcord_client_listen(NULL, test_on_accept_conn, NULL);

    // assert
    CTEST_ASSERT_ARE_NOT_EQUAL(int, 0, result);
    CTEST_ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

CTEST_END_TEST_SUITE(patchcord_client_ut)
