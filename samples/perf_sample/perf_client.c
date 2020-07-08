// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>

#include "lib-util-c/thread_mgr.h"
#include "lib-util-c/alarm_timer.h"
#include "lib-util-c/item_list.h"

#include "patchcords/patchcord_client.h"
#include "patchcords/cord_tls_client.h"
#include "patchcords/cord_socket_client.h"

#include "perf_const.h"

typedef struct INSTRUMENTATION_TAG
{
    time_t time_sent;
    double latency;
    bool in_flight;
} INSTRUMENTATION;

typedef struct PERF_CLIENT_TAG
{
    int error;
    bool socket_open;
    bool send_async;
    ALARM_TIMER_INFO timer;
    ITEM_LIST_HANDLE instrument_list;
    INSTRUMENTATION* latest_send;
} PERF_CLIENT;

static const char PERF_SEND_DATA[MESSAGE_SIZE];

void on_xio_open_complete(void* context, IO_OPEN_RESULT open_result)
{
    PERF_CLIENT* sample = (PERF_CLIENT*)context;
    if (open_result != IO_OPEN_OK)
    {
        sample->error = 1;
        printf("Open failed\n");
    }
    else
    {
        sample->socket_open = true;
        printf("Open complete called");
    }
}

static void on_xio_close_complete(void* context)
{
    PERF_CLIENT* data = (PERF_CLIENT*)context;
    data->socket_open = false;
}

void on_xio_send_complete(void* context, IO_SEND_RESULT send_result)
{
    INSTRUMENTATION* instrument = (INSTRUMENTATION*)context;
    time_t curr_tm = time(NULL);
    instrument->latency = difftime(instrument->time_sent, curr_tm);
    instrument->in_flight = false;
}

void on_xio_bytes_recv(void* context, const unsigned char* buffer, size_t size)
{
}

void on_xio_error(void* context, IO_ERROR_RESULT error_result)
{
    PERF_CLIENT* data = (PERF_CLIENT*)context;
    data->error = 1;
    printf("Error detected\n");
}

static void close_connection(CORD_HANDLE svr_conn, PERF_CLIENT* data)
{
    patchcord_client_close(svr_conn, on_xio_close_complete, &data);

    patchcord_client_destroy(svr_conn);
}

static CORD_HANDLE open_server(PERF_CLIENT* data)
{
    CORD_HANDLE result;

    SOCKETIO_CONFIG config = {0};
    config.hostname = PERF_SERVER_ADDRESS;
    config.port = PERF_SERVER_PORT;
    config.address_type = ADDRESS_TYPE_IP;

    PATCHCORD_CALLBACK_INFO client_info;
    client_info.on_bytes_received = on_xio_bytes_recv;
    client_info.on_bytes_received_ctx = data;
    client_info.on_io_error = on_xio_error;
    client_info.on_io_error_ctx = data;

    if ((result = patchcord_client_create(cord_socket_get_interface(), &config, &client_info)) == NULL)
    {
        printf("Failure creating socket");
    }
    else
    {
        if (patchcord_client_open(result, on_xio_open_complete, data) != 0)
        {
            printf("Failed socket open");
            patchcord_client_destroy(result);
            result = NULL;
        }
        else
        {
            // run till socket is connected
            do
            {
                thread_mgr_sleep(5);
                patchcord_client_process_item(result);
            } while (!data->socket_open);
        }
    }
    return result;
}

static int send_message(CORD_HANDLE svr_conn, PERF_CLIENT* data)
{
    int result;
    if (data->send_async || (data->latest_send == NULL || !data->latest_send->in_flight))
    {
        data->latest_send = (INSTRUMENTATION*)malloc(sizeof(INSTRUMENTATION));

        data->latest_send->time_sent = time(NULL);
        if (patchcord_client_send(svr_conn, PERF_SEND_DATA, MESSAGE_SIZE, on_xio_send_complete, data->latest_send) != 0)
        {
            printf("Failure sending data\r");
            free(data->latest_send);
            result = __LINE__;
        }
        else
        {
            item_list_add_item(data->instrument_list, data->latest_send);
            data->latest_send->in_flight = true;
            result = 0;
        }
    }
    else
    {
        result = 0;
    }
    return result;
}

static void process_perf_info(PERF_CLIENT* data)
{
    size_t msg_cnt = item_list_item_count(data->instrument_list);
    ITERATOR_HANDLE iterator = item_list_iterator(data->instrument_list);

    const INSTRUMENTATION* instrument_item;
    double latency_total = 0.0;
    while ((instrument_item = item_list_get_next(data->instrument_list, &iterator)))
    {
        latency_total += instrument_item->latency;
        item_list_remove_item(data->instrument_list, 0);
    }

    printf("Messages Sent: %zu\n", msg_cnt);
    printf("Avg Latency: %f\n", latency_total);
}

int main()
{
    PERF_CLIENT data = {0};

    CORD_HANDLE svr_conn;
    if (alarm_timer_init(&data.timer) != 0)
    {
        printf("failure initializing timer\n");
    }
    else if ((svr_conn = open_server(&data)) == NULL)
    {
        printf("Failure opening server\r");
    }
    else
    {
        if (alarm_timer_start(&data.timer, PERF_RUNTIME) == 0)
        {
            do
            {
                if (send_message(svr_conn, &data) != 0)
                {
                    break;
                }
                patchcord_client_process_item(svr_conn);
                thread_mgr_sleep(1000);
            } while (!alarm_timer_is_expired(&data.timer));
        }
        // Call close
        close_connection(svr_conn, &data);

        // Write performance information
        process_perf_info(&data);
    }
    return 0;
}