// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "lib-util-c/thread_mgr.h"
#include "lib-util-c/alarm_timer.h"

#include "patchcords/patchcord_client.h"
#include "patchcords/cord_socket_client.h"

#include "perf_const.h"

typedef enum SOCKET_STATE_TAG
{
    IO_STATE_OPEN,
    IO_STATE_DISCONNECTED,
    IO_STATE_CLOSING,
    IO_STATE_CLOSED,
    IO_STATE_ERROR,
    IO_STATE_COMPLETE
} SOCKET_STATE;

typedef struct CLIENT_CONNECTION_TAG
{
    SOCKET_STATE state;
    size_t msg_size;
    uint64_t msg_recieved;
    time_t connect_time;
    PATCH_INSTANCE_HANDLE incoming_socket;
} CLIENT_CONNECTION;

typedef struct PERF_SERVER_TAG
{
    ALARM_TIMER_INFO timer;
    uint32_t max_concurent_conn;
    int error;
    bool socket_open;
    int send_complete;

    // For now
    CLIENT_CONNECTION* client_conn;
} PERF_SERVER;

static void on_server_error(void* context, IO_ERROR_RESULT error_result)
{
    (void)error_result;
    PERF_SERVER* data = (PERF_SERVER*)context;
    data->error = 1;
    printf("Server Error detected\n");
}

static void on_client_close_complete(void* context)
{
    CLIENT_CONNECTION* client_conn = (CLIENT_CONNECTION*)context;
    client_conn->state = IO_STATE_CLOSED;
}

static void process_client_info(CLIENT_CONNECTION* client_conn)
{
    do
    {
        patchcord_client_process_item(client_conn->incoming_socket);

        if (client_conn->state == IO_STATE_DISCONNECTED)
        {
            printf("Client transition DISCONNECTED ==> CLOSING\n");
            // Close the socket
            patchcord_client_close(client_conn->incoming_socket, on_client_close_complete, client_conn);
            client_conn->state = IO_STATE_CLOSING;
        }
        else if (client_conn->state == IO_STATE_CLOSED)
        {
            printf("Client transition CLOSED ==> COMPLETE\n");
            patchcord_client_destroy(client_conn->incoming_socket);
            client_conn->state = IO_STATE_COMPLETE;
        }
        else if (client_conn->state == IO_STATE_ERROR)
        {
            printf("Client transition ERROR ==> CLOSING\n");
            patchcord_client_close(client_conn->incoming_socket, on_client_close_complete, client_conn);
            client_conn->state = IO_STATE_CLOSING;
        }
    } while (client_conn->state != IO_STATE_COMPLETE);

    // Print stats
    printf("Client Statistics:\n");
    double time_conn = difftime(time(NULL), client_conn->connect_time);
    printf("\n\nTime Connected: %.1f\n", time_conn);
    printf("Messages Received: %zu\n", client_conn->msg_recieved);
    if (time_conn != 0)
    {
        printf("Messages per sec: %.1f\n\n", client_conn->msg_recieved/time_conn);
    }
    else
    {
        printf("Messages per sec: 0\n\n");
    }
    free(client_conn);
}

static void on_client_bytes_recv(void* context, const unsigned char* buffer, size_t size, const void* config)
{
    (void)config;
    (void)buffer;
    CLIENT_CONNECTION* client_conn = (CLIENT_CONNECTION*)context;
    client_conn->msg_size += size;
    if (client_conn->msg_size >= MESSAGE_SIZE)
    {
        client_conn->msg_size = 0;
        client_conn->msg_recieved++;
    }
}

static void on_client_error(void* context, IO_ERROR_RESULT error_result)
{
    CLIENT_CONNECTION* client_conn = (CLIENT_CONNECTION*)context;
    client_conn->state = IO_STATE_ERROR;
    printf("Client Error detected %d\n", (int)error_result);
}

static void on_client_close(void* context)
{
    CLIENT_CONNECTION* client_conn = (CLIENT_CONNECTION*)context;
    client_conn->state = IO_STATE_DISCONNECTED;
    printf("Client state DISCONNECTED\n");
}

static void on_accept_conn(void* context, const void* config)
{
    printf("Incoming socket connection\n");

    //const SOCKETIO_CONFIG* socket_config = (const SOCKETIO_CONFIG*)config;
    PERF_SERVER* data = (PERF_SERVER*)context;

    CLIENT_CONNECTION* client_conn = calloc(1, sizeof(CLIENT_CONNECTION));
    if (client_conn == NULL)
    {
        printf("Unable to create client connection\n");
        data->error = 1;
    }
    else
    {
        PATCHCORD_CALLBACK_INFO client_info = { 0 };
        client_info.on_bytes_received = on_client_bytes_recv;
        client_info.on_bytes_received_ctx = client_conn;
        client_info.on_io_error = on_client_error;
        client_info.on_io_error_ctx = client_conn;
        client_info.on_client_close = on_client_close;
        client_info.on_close_ctx = client_conn;

        // TODO: add to thread pool
        client_conn->connect_time = time(NULL);
        client_conn->incoming_socket = patchcord_client_create(cord_socket_get_interface(), config, &client_info);
        if (client_conn->incoming_socket == NULL)
        {
            printf("Unable to create client connection\n");
            free(client_conn);
        }
        else
        {
            client_conn->state = IO_STATE_OPEN;
            data->client_conn = client_conn;
        }
    }
}

int main()
{
    PATCH_INSTANCE_HANDLE xio_handle;
    PERF_SERVER data = {0};
    SOCKETIO_CONFIG config = {0};
    config.hostname = PERF_SERVER_ADDRESS;
    config.port = PERF_SERVER_PORT;
    config.address_type = ADDRESS_TYPE_IP;

    const IO_INTERFACE_DESCRIPTION* io_desc = cord_socket_get_interface();
    PATCHCORD_CALLBACK_INFO client_info = {0};
    client_info.on_io_error = on_server_error;
    client_info.on_io_error_ctx = &data;

    // Create thread pool here;
    if (alarm_timer_init(&data.timer) != 0)
    {
        printf("failure initializing timer\n");
    }
    else if ((xio_handle = patchcord_client_create(io_desc, &config, &client_info)) == NULL)
    {
        printf("Failure creating socket\n");
    }
    else
    {
        printf("Calling listen for the server\n");
        if (patchcord_client_listen(xio_handle, on_accept_conn, &data) != 0)
        {
            printf("Failed socket open\n");
        }
        else if (alarm_timer_start(&data.timer, SERVER_TIMEOUT_RUNTIME) != 0)
        {
            printf("Failure starting timer\n");
        }
        else
        {
            printf("Waiting for connection\n");
            do
            {
                patchcord_client_process_item(xio_handle);

                // Will be handle in thread
                if (data.client_conn != NULL)
                {
                    process_client_info(data.client_conn);
                    data.client_conn = NULL;
                    alarm_timer_reset(&data.timer);
                }
                thread_mgr_sleep(2);
                if (data.error != 0 || alarm_timer_is_expired(&data.timer))
                {
                    break;
                }
            } while (data.error == 0);
        }
        patchcord_client_destroy(xio_handle);
    }
    return 0;
}