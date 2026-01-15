#include "../header_files/VPNController.h"

int VPN_max_print_tag = 0;

void vpn_class_print(std::string classname, std::string str){
    std::string classname_tag = "[" + classname + "] ";
    /*
    int classname_tag_len = classname_tag.length();
    if (classname_tag_len <= VPN_max_print_tag){
        classname_tag.append((VPN_max_print_tag - classname_tag_len), ' ');
    }
    else{
        VPN_max_print_tag = classname_tag_len;
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

void VPNController::readFromWintun(){
    HANDLE WaitEvent = networkInterface.getReadWaitEvent();
    // 65535 is the max size of an IP packet (MTU + overhead)
    BYTE packetBuffer[65535];
    int packetSize;
    DWORD LastError;

    while(1){
        
        packetSize = networkInterface.recv(packetBuffer);
        vpn_class_print("readFromWinton", ("Packet Size: "+std::to_string(packetSize)));
        if (packetSize >= 20){
            vpn_class_print("readFromWinton", "Recieving packet from Wintun");
            networkInterface.packet_print(packetBuffer, packetSize);
            if (secureConnection.send(packetBuffer, packetSize) >= 20){
                vpn_class_print("readFromWinton", "BYTES SENT TO THE SERVER");
            }else{
                vpn_class_print("readFromWinton", "BYTES FAILED TO BE SENT TO SERVER");
            }
            
            networkInterface.releasePacket(packetBuffer);
        }
        else{
            LastError = GetLastError();
            
            switch (LastError){
  
                case ERROR_NO_MORE_ITEMS:
                    vpn_class_print("readFromWinton", "No more items, waiting for some to show up");
                    std::cout << std::endl;
                    if (WaitForSingleObject(WaitEvent, INFINITE) == WAIT_OBJECT_0){
                        continue;
                    }
                    vpn_report_error("Wait for Single Object Failed");
                default:
                    printf("GetLastError #%d.\n", LastError);
                    vpn_report_error("Failed to read packet");
            }   
        }
        std::cout << std::endl;
    }
}

void VPNController::recvFromServer(){
    HANDLE socketEvent = WSACreateEvent();

    SOCKET ssl_sock = secureConnection.getSslSock();
    WSAEventSelect(ssl_sock, socketEvent, FD_READ | FD_CLOSE);

    BYTE packetBuffer[65535];
    int bufferSize;
    int bytes_recieved;
    DWORD waitResult;

    while (1){
        waitResult = WaitForSingleObject(socketEvent, INFINITE);
        if (waitResult == WAIT_OBJECT_0){

            while(1){
                vpn_class_print("recvFromServer", "Packet received from Server");
                bytes_recieved = secureConnection.recv(packetBuffer, bufferSize);
                if (bytes_recieved >= 20){
                    //send packet recieved from server to wintun
                    networkInterface.send(packetBuffer, bytes_recieved);
                    WSAResetEvent(socketEvent); 
                }
                else if (bytes_recieved == 0){
                    //connection closed 
                    vpn_report_error("Connection Closed");

                }
                else if (bytes_recieved < 0){
                    vpn_report_error("SSL error check SSL_get_error");
                }

                if (SSL_pending(secureConnection.getSSLPtr()) == 0) {
                    break;
                }
            }
            WSAResetEvent(socketEvent);
        }
    }   
}

void VPNController::STreadFromWintun(BYTE* byteBuffer){
    int packetSize = networkInterface.recv(byteBuffer);
    if (packetSize >= 20){
        vpn_class_print("STreadFromWinton", "Recieving packet from Wintun");
        networkInterface.packet_print(byteBuffer, packetSize);
        if (secureConnection.send(byteBuffer, packetSize) >= 20){
        }else{
            vpn_class_print("STreadFromWinton", "Bytes failed to send");
        }
        
        networkInterface.releasePacket(byteBuffer);
    }
}

void VPNController::STrecvFromServer(BYTE* byteBuffer, int bufferSize){
     while(1){
        int bytes_recieved = secureConnection.recv(byteBuffer, bufferSize);
        if (bytes_recieved >= 20){
            vpn_class_print("STreadFromWinton", "Recieving packet from Wintun");
            networkInterface.packet_print(byteBuffer, bytes_recieved);
            networkInterface.send(byteBuffer, bytes_recieved);
        }
        else if (bytes_recieved == 0){
            //connection closed 
            vpn_report_error("Connection Closed");

        }
        else if (bytes_recieved < 0){
            vpn_report_error("SSL error check SSL_get_error");
        }

        if (SSL_pending(secureConnection.getSSLPtr()) == 0) {
            break;
        }
    }
}

void VPNController::singleThreadVPN(){
    HANDLE sslEvent = WSACreateEvent();
    SOCKET ssl_sock = secureConnection.getSslSock();
    
    WSAEventSelect(ssl_sock, sslEvent, FD_READ | FD_CLOSE);
    HANDLE wintunEvent = networkInterface.getReadWaitEvent();
    
    HANDLE handles[2];
    handles[0] = wintunEvent;
    handles[1] = sslEvent;
    
    DWORD waitResult;
    BYTE byteBuffer[65535];
    int bufferSize = sizeof(byteBuffer);

    while(1){
        vpn_class_print("singleThreadVPN", "Waiting for a Wintun or SSL packet...");
        waitResult = WaitForMultipleObjects(2, handles, FALSE, INFINITE);
        switch(waitResult){
            case WAIT_OBJECT_0:
                STreadFromWintun(byteBuffer);
                break;
            
            case WAIT_OBJECT_0 + 1:
                STrecvFromServer(byteBuffer, bufferSize);
                WSAResetEvent(sslEvent); 
                break;
            case WAIT_FAILED:
                vpn_class_print("singleThreadVPN", "Error waiting: " + std::to_string(GetLastError()));
                vpn_report_error("Problem with the wait for multi");
        }
        std::cout << std::endl;
    }

}

void VPNController::close(){
    vpn_class_print("close","Properly closing objects");
    //secureConnection.close();
    //networkInterface.close();
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


