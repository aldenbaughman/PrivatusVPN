#pragma once

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <cstdlib>
#include <iostream>
#include <stdint.h>
#include <iostream>

class VirtualNetworkInterface
{
private:
    int m_tunfd;
    struct ifreq m_ifr;
    std::string m_tunIpAddr;

public:
    VirtualNetworkInterface(std::string tunIpAddr);
    void start();
    int getTunFd();
    int tunRead(uint8_t* readBuffer, int bufferSize);
    int tunWrite(uint8_t* packet, int packetSize);
    void ping_test();

};
