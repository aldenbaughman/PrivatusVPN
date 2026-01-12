#include "../header_files/VPNController.h"

void vpn_class_print(std::string classname, std::string str){
    std::string classname_tag = "[" + classname + "] ";
    std::cout << classname_tag << str << std::endl;
}

VPNController::VPNController(ServerSecureConnection& secureConnection, VirtualNetworkInterface& networkInterface)
    : secureConnection(secureConnection), networkInterface(networkInterface)
{

}

void VPNController::start(){
    secureConnection.connect();
    networkInterface.start();
    /*
    std::thread first (&VPNController::readFromTun, this);
    std::thread second (&VPNController::recvFromClient, this);

    first.join();
    second.join();
    */
}

void VPNController::readFromTun(){
    vpn_class_print("readFromTun", "Starting Up Read from Tun");
    struct pollfd pollTun;
    pollTun.fd = networkInterface.getTunFd();
    int pollVal;
    uint8_t packetBuffer[65535];
    int bufferSize = sizeof(packetBuffer);
    int tunPacketSize;

    while(1){
        
        pollVal = poll(&pollTun, 1, -1);
        if (pollVal = 1){
            vpn_class_print("readFromTun","Packet read from tun");
            tunPacketSize = networkInterface.tunRead(packetBuffer, bufferSize);
            if (secureConnection.send(packetBuffer, tunPacketSize) >=20){
                std::cout << "Packet written to wintun successfully" << std::endl;
            }
            else {
                std::cout << "something wrong with wintun" << std::endl;
            }
        }
        else{
            std::cout << "Problem with tun poll" << std::endl;
        }
    }
}

void VPNController::recvFromClient(){
    struct pollfd pollSock;
    pollSock.fd = secureConnection.getSockFd();
    int pollVal;
    uint8_t packetBuffer[65535];
    int bufferSize = sizeof(packetBuffer);
    int clientPacketSize;


    while(1){
        vpn_class_print("recvFromClient", "Starting Up Recieve from Client");
        //pollVal = poll(&pollSock, 1, -1);
        pollVal = 1;
        if (pollVal = 1){
            vpn_class_print("readFromTun","Packet recieved from client");
            clientPacketSize = secureConnection.recv(packetBuffer, bufferSize);
            if (networkInterface.tunWrite(packetBuffer, clientPacketSize) >=20){
                std::cout << "Packet written to wintun successfully" << std::endl;
            }
            else {
                std::cout << "something wrong with wintun" << std::endl;
            }
        }
        else {
            std::cout << "Problem with sock poll" << std::endl;
        }
    }
}


