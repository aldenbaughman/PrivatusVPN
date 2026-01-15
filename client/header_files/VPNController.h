#pragma once

#include <thread>
#include <string>
#include "ClientSecureConnection.h"
#include "VirtualNetworkInterface.h"


class VPNController
{
private:
    ClientSecureConnection secureConnection;
    VirtualNetworkInterface networkInterface;

public:
    VPNController(ClientSecureConnection, VirtualNetworkInterface);
    void start();
    void readFromWintun();
    void recvFromServer();

    void STreadFromWintun(BYTE* byteBuffer);
    void STrecvFromServer(BYTE* byteBuffer, int bufferSize);
    void singleThreadVPN();
    void close();

    void tls_test();
    void wintun_test();
};
