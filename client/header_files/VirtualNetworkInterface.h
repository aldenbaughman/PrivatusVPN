#pragma once

//These are used to initialize ip stuff
#include "wintun.h"
#include <iphlpapi.h>
#include <mstcpip.h>
#include <winternl.h>
#include <ws2tcpip.h>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <netioapi.h>

#include <iostream>
#include <stdexcept>
#include <string>

#include "PacketEnums.h"


class VirtualNetworkInterface
{
private:
    static WINTUN_CREATE_ADAPTER_FUNC* WintunCreateAdapter;
    static WINTUN_CLOSE_ADAPTER_FUNC* WintunCloseAdapter;
    static WINTUN_OPEN_ADAPTER_FUNC* WintunOpenAdapter;
    static WINTUN_GET_ADAPTER_LUID_FUNC* WintunGetAdapterLUID;
    static WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* WintunGetRunningDriverVersion;
    static WINTUN_DELETE_DRIVER_FUNC* WintunDeleteDriver;
    static WINTUN_SET_LOGGER_FUNC* WintunSetLogger;
    static WINTUN_START_SESSION_FUNC* WintunStartSession;
    static WINTUN_END_SESSION_FUNC* WintunEndSession;
    static WINTUN_GET_READ_WAIT_EVENT_FUNC* WintunGetReadWaitEvent;
    static WINTUN_RECEIVE_PACKET_FUNC* WintunReceivePacket;
    static WINTUN_RELEASE_RECEIVE_PACKET_FUNC* WintunReleaseReceivePacket;
    static WINTUN_ALLOCATE_SEND_PACKET_FUNC* WintunAllocateSendPacket;
    static WINTUN_SEND_PACKET_FUNC* WintunSendPacket;

    DWORD m_physicalServerIp;
    DWORD m_virtualServerIp;
    WINTUN_SESSION_HANDLE m_session;
    WINTUN_ADAPTER_HANDLE m_adapter;


public:
    VirtualNetworkInterface(std::string physicalServerIp, std::string virtualServerIp);
    static HMODULE InitializeWintun();
    void start();
    int send(BYTE*, int);
    int recv(BYTE*);
    int releasePacket(BYTE*);
    HANDLE getReadWaitEvent();
    static void packet_print(BYTE* Packet, DWORD PacketSize);
    ~VirtualNetworkInterface();
    void close();
    void ping_test();

};
