// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#else
#include <stdlib.h>
#include <stddef.h>
#endif

#include "ctest.h"
#include "azure_macro_utils/macro_utils.h"
#include "umock_c/umock_c.h"

#define ENABLE_MOCKS
#include "patchcords/xio_client.h"
#include "lib-util-c/crt_extensions.h"

#undef ENABLE_MOCKS

#include "patchcords/xio_socket.h"

static const char* TEST_HOSTNAME = "localhost";
static uint16_t TEST_PORT_VALUE = 8543;

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    CTEST_ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

CTEST_BEGIN_TEST_SUITE(xio_client_e2e)

CTEST_SUITE_INITIALIZE()
{
    umock_c_init(on_umock_c_error);
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

CTEST_FUNCTION(xio_socket_send_data_succeed)
{
    // arrange
    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = TEST_PORT_VALUE;
    config.address_type = ADDRESS_TYPE_IP;

    // act

    // assert

    // cleanup
}

CTEST_END_TEST_SUITE(xio_client_e2e)
