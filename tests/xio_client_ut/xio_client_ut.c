// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#else
#include <stdlib.h>
#include <stddef.h>
#endif

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

#include "patchcords/xio_client.h"

#define ENABLE_MOCKS
#include "umock_c/umock_c_prod.h"
#include "lib-util-c/sys_debug_shim.h"

MOCKABLE_FUNCTION(, XIO_IMPL_HANDLE, test_xio_create, const void*, xio_create_parameters);
MOCKABLE_FUNCTION(, void, test_xio_destroy, XIO_IMPL_HANDLE, handle);
MOCKABLE_FUNCTION(, int, test_xio_open, XIO_IMPL_HANDLE, handle, ON_IO_OPEN_COMPLETE, on_io_open_complete, void*, on_io_open_complete_context, ON_BYTES_RECEIVED, on_bytes_received, void*, on_bytes_received_context, ON_IO_ERROR, on_io_error, void*, on_io_error_context);
MOCKABLE_FUNCTION(, int, test_xio_close, XIO_IMPL_HANDLE, handle, ON_IO_CLOSE_COMPLETE, on_io_close_complete, void*, callback_context);
MOCKABLE_FUNCTION(, int, test_xio_send, XIO_IMPL_HANDLE, handle, const void*, buffer, size_t, size, ON_SEND_COMPLETE, on_send_complete, void*, callback_context);
MOCKABLE_FUNCTION(, void, test_xio_process_item, XIO_IMPL_HANDLE, handle);
MOCKABLE_FUNCTION(, const char*, test_xio_query_endpoint, XIO_IMPL_HANDLE, handle);
#undef ENABLE_MOCKS

static const char* TEST_SEND_BUFFER = "Test send buffer";
static const char* TEST_ENDPOINT = "Test_Endpoint";
static size_t TEST_SEND_BUFFER_LEN = 16;

#ifdef __cplusplus
extern "C" {
#endif
    XIO_IMPL_HANDLE my_test_xio_create(const void* xio_create_parameters)
    {
        (void)xio_create_parameters;
        return (XIO_IMPL_HANDLE)my_mem_shim_malloc(1);
    }

    void my_test_xio_destroy(XIO_IMPL_HANDLE handle)
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
    test_xio_query_endpoint
};

static TEST_MUTEX_HANDLE test_serialize_mutex;

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

BEGIN_TEST_SUITE(xio_client_ut)

TEST_SUITE_INITIALIZE(suite_init)
{
    test_serialize_mutex = TEST_MUTEX_CREATE();
    ASSERT_IS_NOT_NULL(test_serialize_mutex);

    umock_c_init(on_umock_c_error);

    REGISTER_UMOCK_ALIAS_TYPE(XIO_IMPL_HANDLE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_OPEN_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_CLOSE_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_SEND_COMPLETE, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_BYTES_RECEIVED, void*);
    REGISTER_UMOCK_ALIAS_TYPE(ON_IO_ERROR, void*);

    //REGISTER_GLOBAL_MOCK_HOOK(item_destroy_callback, my_item_destroy_cb);

    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_malloc, my_mem_shim_malloc);
    REGISTER_GLOBAL_MOCK_FAIL_RETURN(mem_shim_malloc, NULL);
    REGISTER_GLOBAL_MOCK_HOOK(mem_shim_free, my_mem_shim_free);

    REGISTER_GLOBAL_MOCK_HOOK(test_xio_create, my_test_xio_create);
    REGISTER_GLOBAL_MOCK_HOOK(test_xio_destroy, my_test_xio_destroy);

    REGISTER_GLOBAL_MOCK_RETURN(test_xio_query_endpoint, TEST_ENDPOINT);
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
}

TEST_FUNCTION_CLEANUP(method_cleanup)
{
    TEST_MUTEX_RELEASE(g_testByTest);
}

TEST_FUNCTION(xio_create_succeed)
{
    // arrange
    int parameters = 10;

    STRICT_EXPECTED_CALL(malloc(IGNORED_NUM_ARG));
    STRICT_EXPECTED_CALL(test_xio_create(&parameters));

    // act
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);

    // assert
    ASSERT_IS_NOT_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_client_destroy(handle);
}

TEST_FUNCTION(xio_create_interface_desc_NULL_fail)
{
    // arrange
    int parameters = 10;

    // act
    XIO_INSTANCE_HANDLE handle = xio_client_create(NULL, &parameters);

    // assert
    ASSERT_IS_NULL(handle);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_client_destroy_success)
{
    // arrange
    int parameters = 10;
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_destroy(IGNORED_PTR_ARG));
    STRICT_EXPECTED_CALL(free(IGNORED_PTR_ARG));

    // act
    xio_client_destroy(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_client_destroy_handle_NULL_fail)
{
    // arrange

    // act
    xio_client_destroy(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_client_open_handle_NULL_fail)
{
    // arrange

    // act
    int result = xio_client_open(NULL, test_on_io_open_complete, NULL, test_on_bytes_received, NULL, test_on_io_error, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_client_open_success)
{
    // arrange
    int parameters = 10;
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_open(IGNORED_PTR_ARG, IGNORED_PTR_ARG, NULL, IGNORED_PTR_ARG, NULL, IGNORED_PTR_ARG, NULL));

    // act
    int result = xio_client_open(handle, test_on_io_open_complete, NULL, test_on_bytes_received, NULL, test_on_io_error, NULL);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_client_destroy(handle);
}

TEST_FUNCTION(xio_client_open_fail)
{
    // arrange
    int parameters = 10;
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_open(IGNORED_PTR_ARG, IGNORED_PTR_ARG, NULL, IGNORED_PTR_ARG, NULL, IGNORED_PTR_ARG, NULL)).SetReturn(__LINE__);

    // act
    int result = xio_client_open(handle, test_on_io_open_complete, NULL, test_on_bytes_received, NULL, test_on_io_error, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_client_destroy(handle);
}

TEST_FUNCTION(xio_client_close_handle_NULL_fail)
{
    // arrange

    // act
    int result = xio_client_close(NULL, test_on_io_close_complete, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_client_close_success)
{
    // arrange
    int parameters = 10;
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_close(IGNORED_PTR_ARG, test_on_io_close_complete, NULL));

    // act
    int result = xio_client_close(handle, test_on_io_close_complete, NULL);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_client_destroy(handle);
}

TEST_FUNCTION(xio_client_close_fail)
{
    // arrange
    int parameters = 10;
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_close(IGNORED_PTR_ARG, test_on_io_close_complete, NULL)).SetReturn(__LINE__);

    // act
    int result = xio_client_close(handle, test_on_io_close_complete, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_client_destroy(handle);
}

TEST_FUNCTION(xio_client_send_handle_NULL_fail)
{
    // arrange

    // act
    int result = xio_client_send(NULL, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_client_send_success)
{
    // arrange
    int parameters = 10;
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_send(IGNORED_PTR_ARG, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL));

    // act
    int result = xio_client_send(handle, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL);

    // assert
    ASSERT_ARE_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_client_destroy(handle);
}

TEST_FUNCTION(xio_client_send_fail)
{
    // arrange
    int parameters = 10;
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_send(IGNORED_PTR_ARG, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL)).SetReturn(__LINE__);

    // act
    int result = xio_client_send(handle, TEST_SEND_BUFFER, TEST_SEND_BUFFER_LEN, test_on_send_complete, NULL);

    // assert
    ASSERT_ARE_NOT_EQUAL(int, 0, result);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_client_destroy(handle);
}

TEST_FUNCTION(xio_client_process_item_NULL_fail)
{
    // arrange

    // act
    xio_client_process_item(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_client_process_item_success)
{
    // arrange
    int parameters = 10;
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_process_item(IGNORED_PTR_ARG));

    // act
    xio_client_process_item(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_client_destroy(handle);
}

TEST_FUNCTION(xio_client_query_endpoint_NULL_fail)
{
    // arrange

    // act
    xio_client_query_endpoint(NULL);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
}

TEST_FUNCTION(xio_client_query_endpoint_success)
{
    // arrange
    int parameters = 10;
    XIO_INSTANCE_HANDLE handle = xio_client_create(&io_interface_description, &parameters);
    umock_c_reset_all_calls();

    STRICT_EXPECTED_CALL(test_xio_query_endpoint(IGNORED_PTR_ARG));

    // act
    const char* endpoint = xio_client_query_endpoint(handle);

    // assert
    ASSERT_ARE_EQUAL(char_ptr, TEST_ENDPOINT, endpoint);
    ASSERT_ARE_EQUAL(char_ptr, umock_c_get_expected_calls(), umock_c_get_actual_calls());

    // cleanup
    xio_client_destroy(handle);
}

END_TEST_SUITE(xio_client_ut)
