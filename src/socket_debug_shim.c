// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include <stdlib.h>
#include <stdint.h>

#ifdef WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #include <mstcpip.h>
#else
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netdb.h>
    #include <unistd.h>
#endif

#include "lib-util-c/app_logging.h"

typedef enum SOCKET_SHIM_STATE_TAG
{
    SOCKET_SHIM_STATE_INIT,
    SOCKET_SHIM_STATE_NOT_INIT
} SOCKET_SHIM_STATE;

static SOCKET_SHIM_STATE g_socket_shim_state = SOCKET_SHIM_STATE_NOT_INIT;

static uint64_t g_send_bytes = 0;
static uint64_t g_send_number = 0;
static uint64_t g_recv_bytes = 0;
static uint64_t g_recv_number = 0;

int socket_shim_init(void)
{
    int result;

    if (g_socket_shim_state != SOCKET_SHIM_STATE_NOT_INIT)
    {
        result = __LINE__;
    }
    //else if ((gbnetworkThreadSafeLock = Lock_Init()) == NULL)
    //{
    //    result = __LINE__;
    //}
    else
    {
        g_socket_shim_state = SOCKET_SHIM_STATE_INIT;
        g_send_bytes = 0;
        g_send_number = 0;
        g_recv_bytes = 0;
        g_recv_number = 0;
        result = 0;
    }
    return result;
}

void socket_shim_deinit(void)
{
}

#ifdef WIN32
SOCKET socket_shim_socket(int domain, int type, int protocol)
#else
int socket_shim_socket(int domain, int type, int protocol)
#endif
{
    return socket(domain, type, protocol);
}

#ifdef WIN32
int socket_shim_send(SOCKET sock, const char* buf, int len, int flags)
#else
ssize_t socket_shim_send(int sock, const void* buf, size_t len, int flags)
#endif
{
    if (g_socket_shim_state != SOCKET_SHIM_STATE_INIT)
    {
        // Don't log here by design
    }
    //else if (LOCK_OK != Lock(gbnetworkThreadSafeLock))
    //{
    //    log_error("Failed to get the Lock.");
    //}
    else
    {
        g_send_number++;
        g_send_bytes += len;
        //(void)Unlock(gbnetworkThreadSafeLock);
    }
    return send(sock, buf, len, flags);
}

#ifdef WIN32
int socket_shim_recv(SOCKET sock, char* buf, int len, int flags)
#else
ssize_t socket_shim_recv(int sock, void* buf, size_t len, int flags)
#endif
{
#ifdef WIN32
    int result;
#else
    ssize_t result;
#endif

    result = recv(sock, buf, len, flags);
    if (g_socket_shim_state != SOCKET_SHIM_STATE_INIT)
    {
        // Don't log here by design
    }
    //else if (LOCK_OK != Lock(gbnetworkThreadSafeLock))
    //{
    //    LogError("Failed to get the Lock.");
    //}
    else
    {
        if (result > 0)
        {
            g_recv_bytes += result;
            g_recv_number++;
        }
        //(void)Unlock(gbnetworkThreadSafeLock);
    }
    return result;
}

#ifdef WIN32
int socket_shim_connect(SOCKET sock, const struct sockaddr* addr, int len)
#else
int socket_shim_connect(int sock, __CONST_SOCKADDR_ARG addr, socklen_t len)
#endif
{
    return connect(sock, addr, len);
}

#ifdef WIN32
int socket_shim_getaddrinfo(PCSTR node, PCSTR svc_name, const ADDRINFOA* hints, PADDRINFOA* res)
#else
int socket_shim_getaddrinfo(const char* node, const char* svc_name, const struct addrinfo* hints, struct addrinfo** res)
#endif
{
    return getaddrinfo(node, svc_name, hints, res);
}

int socket_shim_fcntl(int __fd, int __cmd, ...)
{
    (void)__fd;
    (void)__cmd;

    // Todo figure this one out
    return 0;
}

#ifdef WIN32
int socket_shim_shutdown(SOCKET socket, int how)
#else
int socket_shim_shutdown(int socket, int how)
#endif
{
    return shutdown(socket, how);
}

#ifdef WIN32
int socket_shim_close(SOCKET sock)
#else
int socket_shim_close(int sock)
#endif
{
#ifdef WIN32
    return closesocket(sock);
#else
    return close(sock);
#endif
}

#ifdef WIN32
void socket_shim_freeaddrinfo(struct addrinfo* res)
#else
void socket_shim_freeaddrinfo(struct addrinfo* res)
#endif
{
    freeaddrinfo(res);
}

#ifdef WIN32
int socket_shim_ioctlsocket(SOCKET s, long cmd, u_long* argp)
{
    return ioctlsocket(s, cmd, argp);
}

int socket_shim_wsastartup(WORD wVersionRequested, LPWSADATA lpWSAData)
{
    return WSAStartup(wVersionRequested, lpWSAData);
}

int socket_shim_wsagetlasterror(void)
{
    return WSAGetLastError();
}

u_short socket_shim_htons(u_short hostshort)
{
    return htons(hostshort);
}
#endif

#ifdef WIN32
int socket_shim_bind(SOCKET __fd, const struct sockaddr FAR* __addr, int __len)
#else
int socket_shim_bind(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
#endif
{
    return bind(__fd, __addr, __len);
}

#ifdef WIN32
int socket_shim_listen(SOCKET __fd, int __n)
#else
int socket_shim_listen(int __fd, int __n)
#endif
{
    return listen(__fd, __n);
}

#ifdef WIN32
SOCKET socket_shim_accept(SOCKET __fd, struct sockaddr FAR* __addr, int FAR* __addr_len)
#else
int socket_shim_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len)
#endif
{
    return accept(__fd, __addr, __addr_len);
}

uint64_t socket_shim_get_bytes_sent()
{
    uint64_t result;
    if (g_socket_shim_state != SOCKET_SHIM_STATE_INIT)
    {
        log_error("component was not initialized.");
        result = 0;
    }
    //else if (LOCK_OK != Lock(gbnetworkThreadSafeLock))
    //{
    //    log_error("Failed to get the Lock.");
    //    result = 0;
    //}
    else
    {
        result = g_send_bytes;
    }
    return result;
}

uint64_t socket_shim_get_num_sends()
{
    uint64_t result;
    if (g_socket_shim_state != SOCKET_SHIM_STATE_INIT)
    {
        log_error("component was not initialized.");
        result = 0;
    }
    //else if (LOCK_OK != Lock(gbnetworkThreadSafeLock))
    //{
    //    log_error("Failed to get the Lock.");
    //    result = 0;
    //}
    else
    {
        result = g_send_bytes;
    }
    return result;
}

uint64_t socket_shim_get_bytes_recv()
{
    uint64_t result;
    if (g_socket_shim_state != SOCKET_SHIM_STATE_INIT)
    {
        log_error("component was not initialized.");
        result = 0;
    }
    //else if (LOCK_OK != Lock(gbnetworkThreadSafeLock))
    //{
    //    log_error("Failed to get the Lock.");
    //    result = 0;
    //}
    else
    {
        result = g_recv_bytes;
    }
    return result;
}

uint64_t socket_shim_get_num_recv()
{
    uint64_t result;
    if (g_socket_shim_state != SOCKET_SHIM_STATE_INIT)
    {
        log_error("component was not initialized.");
        result = 0;
    }
    //else if (LOCK_OK != Lock(gbnetworkThreadSafeLock))
    //{
    //    log_error("Failed to get the Lock.");
    //    result = 0;
    //}
    else
    {
        result = g_recv_number;
    }
    return result;
}

void socket_shim_reset()
{
    if (g_socket_shim_state != SOCKET_SHIM_STATE_INIT)
    {
        log_error("component was not initialized.");
    }
    //else if (LOCK_OK != Lock(gbnetworkThreadSafeLock))
    //{
    //    log_error("Failed to get the Lock.");
    //}
    else
    {
        g_send_bytes = 0;
        g_send_number = 0;
        g_recv_bytes = 0;
        g_recv_number = 0;
        //(void)Unlock(gbnetworkThreadSafeLock);
    }
}
