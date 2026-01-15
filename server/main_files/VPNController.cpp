#include "../header_files/VPNController.h"

void vpn_class_print(std::string classname, std::string str){
    std::string classname_tag = "[" + classname + "] ";
    std::cout << classname_tag << str << std::endl;
}

void vpn_report_error(const std::string& error_message)
{
	throw std::runtime_error(error_message);
}

void vpn_packet_print(uint8_t* Packet, int PacketSize){
    IPVersion ver = static_cast<IPVersion>(Packet[0] >> 4);

    switch (ver){
        case IPVersion::IPv4:
            vpn_class_print("packet_print", 
                            "IP type: " 
                            + IPVersionToString(ver) 
                            + " | Protocol Type: " 
                            + IPProtocolToString(static_cast<IPProtocol>(Packet[9])) 
                            + " | Size: " 
                            + std::to_string(PacketSize));
            break;
        case IPVersion::IPv6:
            vpn_class_print("packet_print", "IP type: " 
                            + IPVersionToString(ver) 
                            + " | Protocol Type: " 
                            + IPProtocolToString(static_cast<IPProtocol>(Packet[6]))
                            + " | Size: " 
                            + std::to_string(PacketSize));
            break;
        default:
            vpn_class_print("packet_print", "packet has undefined format");
    }
}

VPNController::VPNController(ServerSecureConnection& secureConnection, VirtualNetworkInterface& networkInterface)
    : secureConnection(secureConnection), networkInterface(networkInterface)
{

}

void VPNController::start(){
    secureConnection.connect();
    networkInterface.start();
    
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
                vpn_class_print("readFromTun","SERVER TUN -----> CLIENT SSL");
                vpn_packet_print(packetBuffer, tunPacketSize);
                
            }
            else {
                std::cout << "something wrong with wintun" << std::endl;
            }
        }
        else{
            std::cout << "Problem with tun poll" << std::endl;
        }
        std::cout << std::endl;
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
        pollVal = poll(&pollSock, 1, -1);
        if (pollVal = 1){
            vpn_class_print("recvFromClient","Packet recieved from client");
            clientPacketSize = secureConnection.recv(packetBuffer, bufferSize);
            if (networkInterface.tunWrite(packetBuffer, clientPacketSize) >=20){
                vpn_class_print("recvFromClient","CLIENT SSL -----> SERVER TUN");
                vpn_packet_print(packetBuffer, clientPacketSize);
                
                //std::cout << "Packet written to wintun successfully" << std::endl;
            }
            else {
                std::cout << "something wrong with wintun" << std::endl;
            }
        }
        else {
            std::cout << "Problem with sock poll" << std::endl;
        }
        std::cout << std::endl;
    }
}

void VPNController::STreadFromTun(uint8_t* byteBuffer, int bufferSize){
    vpn_class_print("readFromTun","Packet read from tun");
    int tunPacketSize = networkInterface.tunRead(byteBuffer, bufferSize);
    if (secureConnection.send(byteBuffer, tunPacketSize) >=20){
        vpn_class_print("readFromTun","SERVER TUN -----> CLIENT SSL");
        vpn_packet_print(byteBuffer, tunPacketSize);
        
    }
    else {
        std::cout << "something wrong with wintun" << std::endl;
    }
}

void VPNController::STrecvFromClient(uint8_t* byteBuffer, int bufferSize){
    vpn_class_print("STrecvFromClient","Packet recieved from client");
    int clientPacketSize = secureConnection.recv(byteBuffer, bufferSize);
    if (networkInterface.tunWrite(byteBuffer, clientPacketSize) >=20){
        vpn_class_print("STrecvFromClient","CLIENT SSL -----> SERVER TUN");
        vpn_packet_print(byteBuffer, clientPacketSize);
        
        //std::cout << "Packet written to wintun successfully" << std::endl;
    }
    else {
        std::cout << "something wrong with wintun" << std::endl;
    }
}

void VPNController::singleThreadVPN(){
    vpn_class_print("readFromTun", "Starting Up Read from Tun");
    struct pollfd pollFds[2];
    
    pollFds[0].fd = networkInterface.getTunFd();
    pollFds[0].events = POLLIN;

    pollFds[1].fd = secureConnection.getSockFd();
    pollFds[1].events = POLLIN;

    int pollVal;
    uint8_t byteBuffer[65535];
    int bufferSize = sizeof(byteBuffer);

    while(1){
        vpn_class_print("singleThreadVPN", "Waiting on Wintun and SSL...");
        pollVal = poll(pollFds, 2, -1);
        if (pollVal >= 1){
            
            if (pollFds[0].revents & POLLIN) {
                STreadFromTun(byteBuffer, bufferSize);
            }

            if (pollFds[1].revents & POLLIN) {
                STrecvFromClient(byteBuffer, bufferSize);
            }
        }
        else if (pollVal < 0) {
            
            if (errno == EINTR) {
                    continue;
                }
            perror("Problem with single thread vpn polling");
            vpn_report_error("Problem with single thread vpn polling");
        }
        else {
            vpn_report_error("Polling Timed Out");
        }
        std::cout << std::endl;
    }
    
}


