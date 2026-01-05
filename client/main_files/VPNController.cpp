#include "../header_files/VPNController.h"



void vpn_class_print(std::string classname, std::string str){
    std::string classname_tag = "[" + classname + "] ";
    /*
    int classname_tag_len = classname_tag.length();
    int max_spaces_diff = classname_tag_len - max_print_spaces;
    if (max_spaces_diff > max_print_spaces){
        max_print_spaces = classname_tag_len;
        
    } 
    else if (max_spaces_diff < 0){
        max_spaces_diff *= (-1);
        //std::cout << "Max spaces diff: " << std::to_string(max_spaces_diff) << std::endl;
        classname_tag.append(max_spaces_diff, ' ');
    }
    */
    std::cout << classname_tag << str << std::endl;
}

void vpn_report_error(const std::string& error_message)
{
	throw std::runtime_error(error_message);
}

VPNController::VPNController(ClientSecureConnection secureConnection, VirtualNetworkInterface networkInterface)
    : secureConnection(secureConnection), networkInterface(networkInterface)
{

}

void VPNController::start(){
    secureConnection.connect();
    networkInterface.start();
}

BYTE* VPNController::readFromWintun(){
    HANDLE WaitEvent = networkInterface.getReadWaitEvent();
    // 65535 is the max size of an IP packet (MTU + overhead)
    
    int packetSize;
    DWORD LastError;

    while(1){
        BYTE packetBuffer[65535];
        packetSize = networkInterface.recv(packetBuffer);
        vpn_class_print("readFromWinton", ("Packet Size: "+std::to_string(packetSize)));
        if (packetBuffer && (packetSize >= 20)){
            vpn_class_print("readFromWinton", "Recieving packet from Wintun");
            networkInterface.packet_print(packetBuffer, packetSize);
            secureConnection.send(packetBuffer, packetSize);
            vpn_class_print("readFromWinton", "Packet Sent to Server");
            networkInterface.releasePacket(packetBuffer);
        }
        else{
            LastError = GetLastError();
            
            switch (LastError){
                case ERROR_NO_MORE_ITEMS:
                    vpn_class_print("readFromWinton", "No more items, waiting for some to show up");
                    if (WaitForSingleObject(WaitEvent, INFINITE) == WAIT_OBJECT_0){
                        continue;
                    }
                    vpn_report_error("Wait for Single Object Failed");
                default:
                    printf("GetLastError #%d.\n", LastError);
                    vpn_report_error("Failed to read packet");
            }   
        }
    }
}


void VPNController::tls_test(){
    secureConnection.connect();
    
    int bufferSize = 4096;
    BYTE byteBuffer[bufferSize];
    int bytes_received = secureConnection.recv(byteBuffer, bufferSize);
    std::string server_message(reinterpret_cast<char*>(byteBuffer), bytes_received);
    std::cout << server_message << std::endl;
    
    std::string client_response = "Glad to be here!";
    const BYTE* byteArray = reinterpret_cast<const BYTE*>(client_response.c_str());
    //the number of bytes needed to represent the string
    int length = client_response.length();
    secureConnection.send(byteArray, length);    
}

void wintun_test(){

}
