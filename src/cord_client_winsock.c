// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <mstcpip.h>
#ifdef AF_UNIX_ON_WINDOWS
#include <afunix.h>
#endif

#include "lib-util-c/sys_debug_shim.h"
#include "lib-util-c/crt_extensions.h"
#include "lib-util-c/app_logging.h"
#include "lib-util-c/item_list.h"

#include "patchcords/patchcord_client.h"
#include "patchcords/socket_debug_shim.h"
#include "patchcords/cord_client.h"

#define RECV_BYTES_MAX_VALUE            128

typedef enum SOCKET_STATE_TAG
{
    IO_STATE_CLOSED,
    IO_STATE_CLOSING,
    IO_STATE_OPENING,
    IO_STATE_OPEN,
    IO_STATE_LISTENING,
    IO_STATE_ERROR
} SOCKET_STATE;

typedef enum SOCKET_SEND_RESULT_TAG
{
    SEND_RESULT_SUCCESS,
    SEND_RESULT_NO_ITEMS,
    SEND_RESULT_ERROR,
    SEND_RESULT_WAIT,
    SEND_RESULT_PARTIAL_SEND
} SOCKET_SEND_RESULT;

typedef struct SOCKET_INSTANCE_TAG
{
    SOCKET socket;
    char* hostname;
    uint16_t port;
    SOCKETIO_ADDRESS_TYPE address_type;
    SOCKET_STATE current_state;

    ITEM_LIST_HANDLE pending_list;
    unsigned char recv_bytes[RECV_BYTES_MAX_VALUE];

    // Callbacks
    ON_IO_OPEN_COMPLETE on_io_open_complete;
    void* on_io_open_complete_context;
    ON_BYTES_RECEIVED on_bytes_received;
    void* on_bytes_received_context;
    ON_IO_ERROR on_io_error;
    void* on_io_error_context;
    ON_IO_CLOSE_COMPLETE on_io_close_complete;
    void* on_close_context;

    ON_INCOMING_CONNECT on_incoming_conn;
    void* on_incoming_ctx;
} SOCKET_INSTANCE;

typedef struct PENDING_SEND_ITEM_TAG
{
    const char* send_data;
    size_t data_len;
    ON_SEND_COMPLETE on_send_complete;
    void* send_ctx;
} PENDING_SEND_ITEM;

static void on_pending_list_item_destroy(void* user_ctx, void* remove_item)
{
    (void)user_ctx;
    PENDING_SEND_ITEM* pending_item = (PENDING_SEND_ITEM*)remove_item;
    free(pending_item);
}

static int indicate_error(SOCKET_INSTANCE* socket_impl, IO_ERROR_RESULT err_result)
{
    socket_impl->current_state = IO_STATE_ERROR;
    if (socket_impl->on_io_error != NULL)
    {
        socket_impl->on_io_error(socket_impl->on_io_error_context, err_result);
    }
    return 0;
}

static int select_network_interface(SOCKET_INSTANCE* socket_impl)
{
    (void)socket_impl;
    int result = 0;
    return result;
}

static void close_socket(SOCKET_INSTANCE* socket_impl)
{
    (void)shutdown(socket_impl->socket, SD_BOTH);
    closesocket(socket_impl->socket);
    socket_impl->socket = INVALID_SOCKET;

    if (socket_impl->on_io_close_complete != NULL)
    {
        socket_impl->on_io_close_complete(socket_impl->on_close_context);
    }
}

static int open_socket(SOCKET_INSTANCE* socket_impl)
{
    int result;
    int error_value;
    struct addrinfo addr_info_hint;
    struct sockaddr* connect_addr = NULL;
    socklen_t connect_addr_len = 0;
    struct addrinfo* addr_info_ip = NULL;

    if (select_network_interface(socket_impl) != 0)
    {
        log_error("Failure selecting network interface to connect");
        if (socket_impl->on_io_open_complete != NULL)
        {
            socket_impl->on_io_open_complete(socket_impl->on_io_open_complete_context, IO_OPEN_ERROR);
        }
        socket_impl->current_state = IO_STATE_ERROR;
        result = __LINE__;
    }
    else if (socket_impl->address_type == ADDRESS_TYPE_IP || socket_impl->address_type == ADDRESS_TYPE_UDP)
    {
        char port_value[16];
        memset(&addr_info_hint, 0, sizeof(addr_info_hint));
        addr_info_hint.ai_family = AF_INET;
        addr_info_hint.ai_socktype = SOCK_STREAM;

        sprintf(port_value, "%u", socket_impl->port);
        if ((error_value = getaddrinfo(socket_impl->hostname, port_value, &addr_info_hint, &addr_info_ip)) != 0)
        {
            log_error("Failure getting address info");
            if (socket_impl->on_io_open_complete != NULL)
            {
                socket_impl->on_io_open_complete(socket_impl->on_io_open_complete_context, IO_OPEN_ERROR);
            }
            socket_impl->current_state = IO_STATE_ERROR;
            result = __LINE__;
        }
        else
        {
            connect_addr = addr_info_ip->ai_addr;
            connect_addr_len = sizeof(*addr_info_ip->ai_addr);
            result = 0;
        }
    }
    else
    {
        /*size_t hostname_len = strlen(socket_impl->hostname);
        if (hostname_len + 1 > sizeof(socket_addr.sun_path))
        {
            log_error("Hostname %s is too long for a unix socket (max len = %lu)", socket_impl->hostname, (unsigned long)sizeof(socket_addr.sun_path));
            if (socket_impl->on_io_open_complete != NULL)
            {
                socket_impl->on_io_open_complete(socket_impl->on_io_open_complete_context, IO_OPEN_ERROR);
            }
            socket_impl->current_state = IO_STATE_ERROR;
            result = MU_FAILURE;
        }
        else
        {
            memset(&socket_addr, 0, sizeof(socket_addr));
            socket_addr.sun_family = AF_UNIX;
            // No need to add NULL terminator due to the above memset
            (void)memcpy(socket_addr.sun_path, socket_impl->hostname, hostname_len);

            connect_addr = (struct sockaddr*)&socket_addr;
            connect_addr_len = sizeof(socket_addr);
            result = 0;
        }*/
        connect_addr_len = 0;
        result = 0;
    }

    if (result == 0)
    {
        u_long mode = 1;

        error_value = connect(socket_impl->socket, connect_addr, connect_addr_len);
        if ((error_value != 0) && (errno != EINPROGRESS))
        {
            // Todo: Convert error to an error message in cb
            log_error("Failure: connect failure %d.", errno);
            if (socket_impl->on_io_open_complete != NULL)
            {
                socket_impl->on_io_open_complete(socket_impl->on_io_open_complete_context, IO_OPEN_ERROR);
            }
            result = __LINE__;
        }
        else if (ioctlsocket(socket_impl->socket, FIONBIO, &mode) != 0)
        {
            log_error("Failure: ioctlsocket failure %d.", errno);
            if (socket_impl->on_io_open_complete != NULL)
            {
                socket_impl->on_io_open_complete(socket_impl->on_io_open_complete_context, IO_OPEN_ERROR);
            }
            result = __LINE__;
        }
        else
        {
            if (socket_impl->on_io_open_complete != NULL)
            {
                socket_impl->on_io_open_complete(socket_impl->on_io_open_complete_context, IO_OPEN_OK);
            }
            result = 0;
        }
    }
    if (addr_info_ip != NULL)
    {
        freeaddrinfo(addr_info_ip);
    }
    return result;
}

static int construct_socket_object(SOCKET_INSTANCE* socket_impl)
{
    int result;
    if (socket_impl->address_type == ADDRESS_TYPE_UDP)
    {
        socket_impl->socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    }
    else if (socket_impl->address_type == ADDRESS_TYPE_DOMAIN_SOCKET)
    {
        socket_impl->socket = socket(AF_UNIX, SOCK_STREAM, 0);
    }
    else
    {
        socket_impl->socket = socket(AF_INET, SOCK_STREAM, 0);
    }

    if (socket_impl->socket == INVALID_SOCKET)
    {
        log_error("Failure on socket call");
        result = __LINE__;
    }
    else
    {
        result = 0;
    }
    return result;
}

static int recv_socket_data(SOCKET_INSTANCE* socket_impl)
{
    int result;
    if (socket_impl->on_bytes_received == NULL)
    {
        // No receive callback so don't receive
        result = 0;
    }
    else
    {
        int recv_res = recv(socket_impl->socket, (char*)socket_impl->recv_bytes, RECV_BYTES_MAX_VALUE, 0);
        if (recv_res > 0)
        {
            socket_impl->on_bytes_received(socket_impl->on_bytes_received_context, socket_impl->recv_bytes, recv_res);
            result = 0;
        }
        else if (recv_res == 0)
        {
            indicate_error(socket_impl, IO_ERROR_SERVER_DISCONN);
            result = __LINE__;
        }
        else
        {
            int last_sock_error = WSAGetLastError();
            log_error("Failure receiving data on the socket, errno: %d (%s)", last_sock_error, "Failure");
            indicate_error(socket_impl, IO_ERROR_GENERAL);
            result = __LINE__;
        }
    }
    return result;
}

static SOCKET_SEND_RESULT send_socket_data(SOCKET_INSTANCE* socket_impl, PENDING_SEND_ITEM* pending_item)
{
    SOCKET_SEND_RESULT result;

    // Send the current item
    int send_res = send(socket_impl->socket, pending_item->send_data, (int)pending_item->data_len, 0);
    if (send_res  != (int)pending_item->data_len)
    {
        int last_sock_error = WSAGetLastError();
        if (send_res == SOCKET_ERROR)
        {
            if (last_sock_error != WSAEWOULDBLOCK)
            {
                // Failure happened
                if (pending_item->on_send_complete != NULL)
                {
                    pending_item->on_send_complete(pending_item->send_ctx, IO_SEND_ERROR);
                }
                log_error("Failure sending data on the socket, errno: %d (%s)", last_sock_error, "Failure"); // last_sock_error
                result = SEND_RESULT_ERROR;
            }
            else
            {
                // Queue it up for the next call
                if (item_list_add_item(socket_impl->pending_list, pending_item) != 0)
                {
                    if (pending_item->on_send_complete != NULL)
                    {
                        pending_item->on_send_complete(pending_item->send_ctx, IO_SEND_ERROR);
                    }
                    log_error("Failure allocating malloc");
                    result = SEND_RESULT_ERROR;
                }
                else
                {
                    result = SEND_RESULT_WAIT;
                }
            }
        }
        else
        {
            // Partial send
            pending_item->send_data += send_res;
            pending_item->data_len -= send_res;
            if (item_list_add_item(socket_impl->pending_list, pending_item) != 0)
            {
                indicate_error(socket_impl, IO_ERROR_MEMORY);

                // if (pending_item->on_send_complete != NULL)
                // {
                //     pending_item->on_send_complete(pending_item->send_ctx, IO_SEND_ERROR);
                // }
                log_error("Failure allocating malloc");
                result = SEND_RESULT_ERROR;
            }
            else
            {
                result = SEND_RESULT_PARTIAL_SEND;
            }
        }
    }
    else
    {
        // Send success free the memory
        if (pending_item->on_send_complete != NULL)
        {
            pending_item->on_send_complete(pending_item->send_ctx, IO_SEND_OK);
        }
        result = SEND_RESULT_SUCCESS;
    }
    return result;
}

static SOCKET_SEND_RESULT send_socket_cached_data(SOCKET_INSTANCE* socket_impl)
{
    SOCKET_SEND_RESULT result;
    // Now check to see if we have pending sends
    PENDING_SEND_ITEM* pending_item = (PENDING_SEND_ITEM*)item_list_get_front(socket_impl->pending_list);
    if (pending_item != NULL)
    {
        result = send_socket_data(socket_impl, pending_item);
        if (result == SEND_RESULT_SUCCESS)
        {
            if (item_list_remove_item(socket_impl->pending_list, 0) != 0)
            {
                indicate_error(socket_impl, IO_ERROR_GENERAL);
                result = SEND_RESULT_ERROR;
            }
            else
            {
                result = SEND_RESULT_SUCCESS;
            }
        }
    }
    else
    {
        // No items to send
        result = SEND_RESULT_NO_ITEMS;
    }
    return result;
}

CORD_HANDLE cord_client_create(const void* parameters, ON_BYTES_RECEIVED on_bytes_received, void* on_bytes_received_context, ON_IO_ERROR on_io_error, void* on_io_error_context)
{
    SOCKET_INSTANCE* result;
    WSADATA wsa_data;
    int res_value;
    if (parameters == NULL)
    {
        log_error("Invalid parameter specified");
        result = NULL;
    }
    else if ((res_value = WSAStartup(MAKEWORD(2, 2), &wsa_data)) != NO_ERROR)
    {
        log_error("WSAStartup failed with error: %d", res_value);
        result = NULL;
    }
    else if ((result = malloc(sizeof(SOCKET_INSTANCE))) == NULL)
    {
        log_error("Failure allocating socket instance");
    }
    else
    {
        const SOCKETIO_CONFIG* config = (const SOCKETIO_CONFIG*)parameters;
        memset(result, 0, sizeof(SOCKET_INSTANCE));
        result->port = config->port;
        result->address_type = config->address_type;

        // Copy the host name
        if ((result->pending_list = item_list_create(on_pending_list_item_destroy, result)) == NULL)
        {
            log_error("Failure creating pending list item");
            free(result);
            result = NULL;
        }
        else if (clone_string(&result->hostname, config->hostname) != 0)
        {
            log_error("Failure cloning hostname value");
            item_list_destroy(result->pending_list);
            free(result);
            result = NULL;
        }
        else
        {
            result->on_bytes_received = on_bytes_received;
            result->on_bytes_received_context = on_bytes_received_context;
            result->on_io_error = on_io_error;
            result->on_io_error_context = on_io_error_context;
        }
    }
    return (CORD_HANDLE)result;
}

void cord_client_destroy(CORD_HANDLE xio)
{
    if (xio != NULL)
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
        free(socket_impl->hostname);
        item_list_destroy(socket_impl->pending_list);
        free(socket_impl);
        WSACleanup();
    }
}

int cord_client_open(CORD_HANDLE xio, ON_IO_OPEN_COMPLETE on_io_open_complete, void* on_io_open_complete_context)
{
    int result;
    if (xio == NULL)
    {
        log_error("Invalid parameter specified");
        result = __LINE__;
    }
    else
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
        if (socket_impl->current_state == IO_STATE_OPENING || socket_impl->current_state == IO_STATE_OPEN)
        {
            log_error("Socket is in invalid state to open");
            result = __LINE__;
        }
        else if (construct_socket_object(socket_impl) != 0)
        {
            log_error("Failure constructing socket");
            result = __LINE__;
        }
        else
        {
            socket_impl->current_state = IO_STATE_OPENING;
            socket_impl->on_io_open_complete = on_io_open_complete;
            socket_impl->on_io_open_complete_context = on_io_open_complete_context;
            result = 0;
        }
    }
    return result;
}

int cord_client_listen(CORD_HANDLE xio, ON_INCOMING_CONNECT incoming_conn_cb, void* user_ctx)
{
    uint16_t result;
    if (xio == NULL || incoming_conn_cb == NULL)
    {
        log_error("Failure invalid parameter specified xio: %p, incoming_conn_cb: %p", xio, incoming_conn_cb);
        result = __LINE__;
    }
    else
    {
        u_long mode = 1;
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
        (void)user_ctx;
        if (socket_impl->current_state == IO_STATE_OPENING || socket_impl->current_state == IO_STATE_OPEN)
        {
            log_error("Socket is in invalid state to open");
            result = __LINE__;
        }
        else if (socket_impl->address_type != ADDRESS_TYPE_IP)
        {
            log_error("Socket is in an invalid state");
            result = __LINE__;
        }
        else if (construct_socket_object(socket_impl) != 0)
        {
            log_error("Failure constructing socket");
            result = __LINE__;
        }
        else if (ioctlsocket(socket_impl->socket, FIONBIO, &mode) != 0)
        {
            log_error("Failure Setting unblocking socket");
            close_socket(socket_impl);
            result = __LINE__;
        }
        else
        {
            struct sockaddr_in serv_addr = { 0 };
            serv_addr.sin_family = AF_INET;
            serv_addr.sin_addr.s_addr = INADDR_ANY;
            serv_addr.sin_port = htons(socket_impl->port);

            // bind the host address using bind() call
            if (bind(socket_impl->socket, (struct sockaddr*)&serv_addr, sizeof(serv_addr)) < 0)
            {
                log_error("Failure binding to socket address");
                close_socket(socket_impl);
                result = __LINE__;
            }
            else if (listen(socket_impl->socket, SOMAXCONN) < 0)
            {
                log_error("Failure listening to incoming connection");
                close_socket(socket_impl);
                result = __LINE__;
            }
            else
            {
                socket_impl->current_state = IO_STATE_LISTENING;
                socket_impl->on_incoming_conn = incoming_conn_cb;
                socket_impl->on_incoming_ctx = user_ctx;
                result = 0;
            }
        }
    }
    return result;
}

int cord_client_close(CORD_HANDLE xio, ON_IO_CLOSE_COMPLETE on_io_close_complete, void* ctx)
{
    int result;
    if (xio == NULL)
    {
        log_error("Invalid xio parameter");
        result = __LINE__;
    }
    else
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
        if (socket_impl->current_state == IO_STATE_CLOSED || socket_impl->current_state == IO_STATE_CLOSING)
        {
            log_error("Failure can not close while already closing");
            result = __LINE__;
        }
        else
        {
            socket_impl->current_state = IO_STATE_CLOSING;
            socket_impl->on_io_close_complete = on_io_close_complete;
            socket_impl->on_close_context = ctx;
            result = 0;
        }
    }
    return result;
}

int cord_client_send(CORD_HANDLE xio, const void* buffer, size_t size, ON_SEND_COMPLETE on_send_complete, void* callback_context)
{
    int result;
    if (xio == NULL || buffer == NULL || size == 0)
    {
        log_error("Invalid parameter xio: %p, buffer: %p, size: %d", xio, buffer, (int)size);
        result = MU_FAILURE;
    }
    else
    {
        PENDING_SEND_ITEM* send_item;
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
        // If the current state is open, then just try to send the data
        if (socket_impl->current_state != IO_STATE_OPEN)
        {
            log_error("Failure sending in incorrect state");
            result = MU_FAILURE;
        }
        else if ((send_item = (PENDING_SEND_ITEM*)malloc(sizeof(PENDING_SEND_ITEM))) == NULL)
        {
            log_error("Failure allocating malloc");
            result = MU_FAILURE;
        }
        else
        {
            send_item->on_send_complete = on_send_complete;
            send_item->send_ctx = callback_context;
            send_item->send_data = buffer;
            send_item->data_len = size;

            SOCKET_SEND_RESULT send_res = send_socket_data(socket_impl, send_item);
            if (send_res != SEND_RESULT_SUCCESS)
            {
                log_error("Failure attempting to send socket data");
                free(send_item);
                result = MU_FAILURE;
            }
            else if (send_res == SEND_RESULT_SUCCESS)
            {
                free(send_item);
                result = 0;
            }
            else
            {
                // Partial send, don't free wait for the dowork
                result = 0;
            }
        }
    }
    return result;
}

void cord_client_process_item(CORD_HANDLE xio)
{
    if (xio != NULL)
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;

        if (socket_impl->current_state == IO_STATE_OPENING)
        {
            // Open the socket
            if (open_socket(socket_impl) != 0)
            {
                socket_impl->current_state = IO_STATE_ERROR;
            }
            else
            {
                socket_impl->current_state = IO_STATE_OPEN;
            }
        }
        else if (socket_impl->current_state == IO_STATE_CLOSING)
        {
            close_socket(socket_impl);
            socket_impl->current_state = IO_STATE_CLOSED;
        }
        else if (socket_impl->current_state == IO_STATE_OPEN)
        {
            // Going into the send/recv loop.  Keep trying to send the data until:
            // 1. there isn't anything to send
            // 2. there was an error
            // 3. We have a wait or partial send (the socket is backed up)
            // 4. Data was recieved so we probably should send the data
            bool cont_process_loop = true;
            do
            {
                if (send_socket_cached_data(socket_impl) != SEND_RESULT_SUCCESS)
                {
                    cont_process_loop = false;
                }
                if (recv_socket_data(socket_impl) != 0)
                {
                    cont_process_loop = false;
                }
            } while (cont_process_loop);
        }
        else if (socket_impl->current_state == IO_STATE_LISTENING)
        {
            struct sockaddr_in cli_addr;
            socklen_t client_len = sizeof(cli_addr);
            // Accept actual connection from the client
            SOCKET accepted_socket = accept(socket_impl->socket, (struct sockaddr *)&cli_addr, &client_len);
            if (accepted_socket != SOCKET_ERROR)
            {
                u_long mode = 1;
                if (ioctlsocket(socket_impl->socket, FIONBIO, &mode) != 0)
                {
                    log_error("Failure setting accepted socket to non blocking");
                    (void)shutdown(accepted_socket, SD_BOTH);
                    closesocket(accepted_socket);
                }
                else
                {
                    SOCKETIO_CONFIG config = { 0 };
                    config.port = cli_addr.sin_port;
                    config.accepted_socket = &accepted_socket;
                    socket_impl->on_incoming_conn(socket_impl->on_incoming_ctx, &config);
                }
            }
        }
        else
        {

        }
    }
}

const char* cord_client_query_uri(CORD_HANDLE xio)
{
    const char* result;
    if (xio == NULL)
    {
        log_error("Failure invalid parameter specified xio: NULL");
        result = NULL;
    }
    else
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
        result = socket_impl->hostname;
    }
    return result;
}

uint16_t cord_client_query_port(CORD_HANDLE xio)
{
    uint16_t result;
    if (xio == NULL)
    {
        log_error("Failure invalid parameter specified xio: NULL");
        result = 0;
    }
    else
    {
        SOCKET_INSTANCE* socket_impl = (SOCKET_INSTANCE*)xio;
        result = socket_impl->port;
    }
    return result;
}

static const IO_INTERFACE_DESCRIPTION socket_io_interface =
{
    cord_client_create,
    cord_client_destroy,
    cord_client_open,
    cord_client_close,
    cord_client_send,
    cord_client_process_item,
    cord_client_query_uri,
    cord_client_query_port,
    cord_client_listen
};

const IO_INTERFACE_DESCRIPTION* xio_cord_get_interface(void)
{
    return &socket_io_interface;
}