#ifndef VIRTUAL_NETWORK_INTERFACE
#define VIRTUAL_NETWORK_INTERFACE

#include <iostream>
#include <stdexcept>
#include <string>
#include "wintun.h"

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

public:
    VirtualNetworkInterface();
    static HMODULE InitializeWintun();

};

#endif
