// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#ifdef __cplusplus
#include <cstdlib>
#include <cstddef>
#else
#include <stdlib.h>
#include <stddef.h>
#include <stdbool.h>
#endif

#include "ctest.h"
#include "macro_utils/macro_utils.h"
#include "umock_c/umock_c.h"

#include "lib-util-c/crt_extensions.h"
#include "lib-util-c/buffer_alloc.h"
#include "lib-util-c/app_logging.h"
#include "lib-util-c/thread_mgr.h"
#include "lib-util-c/alarm_timer.h"

#include "patchcords/patchcord_client.h"
#include "patchcords/cord_socket_client.h"

#define SEND_BYTE_SIZE_32           32
#define SEND_BYTE_SIZE_128          128
#define SEND_BYTE_SIZE_1024         1024
#define OPERATION_TIMEOUT_SEC       30

static const char* TEST_HOSTNAME = "localhost";
static uint32_t TEST_32_BYTES_SEND[SEND_BYTE_SIZE_32];
static uint32_t TEST_128_BYTES_SEND[SEND_BYTE_SIZE_128];
static uint32_t TEST_1024_BYTES_SEND[SEND_BYTE_SIZE_1024];

typedef enum CLIENT_E2E_STATE_TAG
{
    CLIENT_STATE_CONN,
    CLIENT_STATE_CONNECTING,
    CLIENT_STATE_SENDING,
    CLIENT_STATE_RECEIVING,
    CLIENT_STATE_RECEIVED,
    CLIENT_STATE_CLOSE,
    CLIENT_STATE_CLOSING,
    CLIENT_STATE_ERROR,
    CLIENT_STATE_COMPLETE
} CLIENT_E2E_STATE;

typedef struct CLIENT_E2E_DATA_TAG
{
    CLIENT_E2E_STATE client_state;
    size_t connect_cnt;
    size_t close_cnt;
    bool test_complete;

    PATCH_INSTANCE_HANDLE incoming;
    IO_ERROR_RESULT error_result;
    BYTE_BUFFER sent_data;

    ALARM_TIMER_INFO timer;
} CLIENT_E2E_DATA;

MU_DEFINE_ENUM_STRINGS(UMOCK_C_ERROR_CODE, UMOCK_C_ERROR_CODE_VALUES)
static void on_umock_c_error(UMOCK_C_ERROR_CODE error_code)
{
    CTEST_ASSERT_FAIL("umock_c reported error :%s", MU_ENUM_TO_STRING(UMOCK_C_ERROR_CODE, error_code));
}

CTEST_BEGIN_TEST_SUITE(patchcord_client_e2e)

CTEST_SUITE_INITIALIZE()
{
    umock_c_init(on_umock_c_error);

    uint32_t data_bytes = 0x10;
    for (size_t index = 0; index < 1024; index++)
    {
        if (index < 32)
        {
            TEST_32_BYTES_SEND[index] = data_bytes++;
        }
        if (index < 128)
        {
            TEST_128_BYTES_SEND[index] = (129) + data_bytes++;
        }
        TEST_1024_BYTES_SEND[index] = (161) + data_bytes++;
    }
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

static PATCH_INSTANCE_HANDLE create_io_ip_socket_objects(const SOCKETIO_CONFIG* config, const PATCHCORD_CALLBACK_INFO* client_cb)
{
    PATCH_INSTANCE_HANDLE result;

    const IO_INTERFACE_DESCRIPTION* io_interface_description = cord_socket_get_interface();

    // Create the listener
    result = patchcord_client_create(io_interface_description, config, client_cb);
    CTEST_ASSERT_IS_NOT_NULL(result);

    return result;
}

// Callbacks
static void on_socket_send_complete_cb(void* context, IO_SEND_RESULT send_result)
{
    (void)send_result;
    CLIENT_E2E_DATA* e2e_data = (CLIENT_E2E_DATA*)context;
    CTEST_ASSERT_IS_NOT_NULL(e2e_data, "on_socket_send_complete_cb context NULL");
}

static void on_socket_error_cb(void* context, IO_ERROR_RESULT error_result)
{
    log_debug("on_socket_error_cb called");
    CLIENT_E2E_DATA* e2e_data = (CLIENT_E2E_DATA*)context;
    CTEST_ASSERT_IS_NOT_NULL(e2e_data, "on_socket_error_cb context NULL");

    e2e_data->error_result = error_result;
    e2e_data->client_state = CLIENT_STATE_ERROR;
}

static void on_socket_bytes_recv_cb(void* context, const unsigned char* buffer, size_t size, const void* config)
{
    (void)config;
    log_debug("on_socket_bytes_recv_cb called");
    CLIENT_E2E_DATA* e2e_data = (CLIENT_E2E_DATA*)context;
    CTEST_ASSERT_IS_NOT_NULL(e2e_data, "on_socket_bytes_recv_cb context NULL");

    CTEST_ASSERT_ARE_EQUAL(int, 0, byte_buffer_construct(&e2e_data->sent_data, buffer, size), "Failure allocating send_data of size %d", (int)size);
}

static void on_socket_connect_cb(void* context, const void* config)
{
    log_debug("on_socket_connect_cb called");

    CLIENT_E2E_DATA* e2e_data = (CLIENT_E2E_DATA*)context;
    CTEST_ASSERT_IS_NOT_NULL(e2e_data, "on_socket_connect_cb context NULL");

    log_debug("Creating the incoming socket which should be the listening socket");
    PATCHCORD_CALLBACK_INFO client_cb;
    client_cb.on_bytes_received = on_socket_bytes_recv_cb;
    client_cb.on_io_error = on_socket_error_cb;
    client_cb.on_bytes_received_ctx = client_cb.on_io_error_ctx = e2e_data;
    e2e_data->incoming = create_io_ip_socket_objects(config, &client_cb);
    CTEST_ASSERT_IS_NOT_NULL(e2e_data->incoming, "Failed to create incoming socket");
}

static void on_socket_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    (void)open_result;
    log_debug("on_socket_open_complete called");
    CLIENT_E2E_DATA* e2e_data = (CLIENT_E2E_DATA*)context;
    CTEST_ASSERT_IS_NOT_NULL(e2e_data, "on_socket_open_complete context NULL");

    e2e_data->connect_cnt++;
}

static void on_socket_close_complete_cb(void* context)
{
    log_debug("on_socket_close_complete_cb called");
    CLIENT_E2E_DATA* e2e_data = (CLIENT_E2E_DATA*)context;
    CTEST_ASSERT_IS_NOT_NULL(e2e_data, "on_socket_close_complete_cb context NULL");

    e2e_data->close_cnt++;
}

static void on_socket_send_complete(void* context, IO_SEND_RESULT send_result)
{
    (void)send_result;
    log_debug("on_socket_send_complete called");

    CLIENT_E2E_DATA* e2e_data = (CLIENT_E2E_DATA*)context;
    CTEST_ASSERT_IS_NOT_NULL(e2e_data, "on_socket_send_complete context NULL");
}

static void set_current_state(CLIENT_E2E_DATA* e2e_data, CLIENT_E2E_STATE new_state)
{
    e2e_data->client_state = new_state;
    alarm_timer_reset(&e2e_data->timer);
}

static void test_socket_sending(uint16_t port, uint32_t* send_data, uint32_t byte_len)
{
    // arrange
    int result;
    CLIENT_E2E_DATA e2e_data = {0};
    PATCH_INSTANCE_HANDLE sender = NULL;
    PATCH_INSTANCE_HANDLE listener = NULL;

    PATCHCORD_CALLBACK_INFO client_cb;
    client_cb.on_bytes_received = on_socket_bytes_recv_cb;
    client_cb.on_io_error = on_socket_error_cb;
    client_cb.on_bytes_received_ctx = client_cb.on_io_error_ctx = &e2e_data;

    SOCKETIO_CONFIG config = {0};
    config.hostname = TEST_HOSTNAME;
    config.port = port;
    config.address_type = ADDRESS_TYPE_IP;

    result = alarm_timer_init(&e2e_data.timer);
    CTEST_ASSERT_ARE_EQUAL(int, 0, result);

    log_debug("Creating listening and sending sockets");
    listener = create_io_ip_socket_objects(&config, &client_cb);
    sender = create_io_ip_socket_objects(&config, &client_cb);

    // Create the socket
    result = patchcord_client_listen(listener, on_socket_connect_cb, &e2e_data);
    CTEST_ASSERT_ARE_EQUAL(int, 0, result, "Unable to call patchcord_client_listen");

    result = alarm_timer_start(&e2e_data.timer, OPERATION_TIMEOUT_SEC);
    CTEST_ASSERT_ARE_EQUAL(int, 0, result, "Unable to start timer");

    do
    {
        switch (e2e_data.client_state)
        {
            case CLIENT_STATE_CONN:
            {
                result = patchcord_client_open(sender, on_socket_open_complete, &e2e_data);
                CTEST_ASSERT_ARE_EQUAL(int, 0, result);
                set_current_state(&e2e_data, CLIENT_STATE_CONNECTING);
                break;
            }
            case CLIENT_STATE_CONNECTING:
                if (e2e_data.connect_cnt >= 1)
                {
                    set_current_state(&e2e_data, CLIENT_STATE_SENDING);
                }
                break;
            case CLIENT_STATE_SENDING:
                log_debug("Sending %d bytes of data", byte_len);
                result = patchcord_client_send(sender, send_data, byte_len, on_socket_send_complete, &e2e_data);
                CTEST_ASSERT_ARE_EQUAL(int, 0, result, "Failure to call patchcord_client_send");
                set_current_state(&e2e_data, CLIENT_STATE_RECEIVING);
                break;
            case CLIENT_STATE_RECEIVING:
                if (e2e_data.sent_data.payload_size >= byte_len)
                {
                    set_current_state(&e2e_data, CLIENT_STATE_RECEIVED);
                }
                break;
            case CLIENT_STATE_RECEIVED:
            {
                // Compare the data sizes
                int cmp_result = memcmp(e2e_data.sent_data.payload, send_data, e2e_data.sent_data.payload_size);
                CTEST_ASSERT_ARE_EQUAL(int, 0, cmp_result, "Failure: The data receivied not equal to data sent");

                byte_buffer_free(&e2e_data.sent_data);
                e2e_data.sent_data.payload = NULL;
                set_current_state(&e2e_data, CLIENT_STATE_CLOSE);
                break;
            }
            case CLIENT_STATE_CLOSE:
                result = patchcord_client_close(sender, on_socket_close_complete_cb, &e2e_data);
                CTEST_ASSERT_ARE_EQUAL(int, 0, result);
                result = patchcord_client_close(e2e_data.incoming, on_socket_close_complete_cb, &e2e_data);
                CTEST_ASSERT_ARE_EQUAL(int, 0, result);
                result = patchcord_client_close(listener, on_socket_close_complete_cb, &e2e_data);
                CTEST_ASSERT_ARE_EQUAL(int, 0, result);
                set_current_state(&e2e_data, CLIENT_STATE_CLOSING);
                break;
            case CLIENT_STATE_CLOSING:
                if (e2e_data.close_cnt >= 3)
                {
                    e2e_data.test_complete = true;
                    set_current_state(&e2e_data, CLIENT_STATE_COMPLETE);
                }
                break;
            case CLIENT_STATE_ERROR:
                CTEST_ASSERT_FAIL("Failure socket encountered %d", (int)e2e_data.error_result);
                break;
        }
        if (e2e_data.incoming != NULL)
        {
            patchcord_client_process_item(e2e_data.incoming);
        }
        patchcord_client_process_item(listener);
        patchcord_client_process_item(sender);

        if (alarm_timer_is_expired(&e2e_data.timer))
        {
            CTEST_ASSERT_FAIL("Failure socket has timed out on operation %d", (int)e2e_data.client_state);
        }
        thread_mgr_sleep(5);
    } while (!e2e_data.test_complete);

    // Cleanup
    patchcord_client_destroy(e2e_data.incoming);
    patchcord_client_destroy(sender);
    patchcord_client_destroy(listener);
}

CTEST_FUNCTION(cord_client_send_32_byte_data_succeed)
{
    static uint16_t port_value = 8440;
    test_socket_sending(port_value, TEST_32_BYTES_SEND, SEND_BYTE_SIZE_32);
}

CTEST_FUNCTION(cord_client_send_128_byte_data_succeed)
{
    static uint16_t port_value = 8441;
    test_socket_sending(port_value, TEST_128_BYTES_SEND, SEND_BYTE_SIZE_128);
}

CTEST_FUNCTION(cord_client_send_1024_byte_data_succeed)
{
    static uint16_t port_value = 8442;
    test_socket_sending(port_value, TEST_1024_BYTES_SEND, SEND_BYTE_SIZE_1024);
}

CTEST_END_TEST_SUITE(patchcord_client_e2e)

