#pragma once

#include "../header_files/ServerSecureConnection.h"
#include "../header_files/VirtualNetworkInterface.h"
#include <poll.h>
#include <thread>

class VPNController
{
private:
    ServerSecureConnection& secureConnection;
    VirtualNetworkInterface& networkInterface;

public:
    VPNController(ServerSecureConnection& secureConnection, VirtualNetworkInterface& networkInterface);
    void start();
    void readFromTun();
    void recvFromClient();
};
