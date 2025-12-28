#include "../header_files/ClientSecureConnection.h"
#include <iostream>
#include <stdexcept>

void ClientSecureConnection::report_error(const std::string& error_message)
{
	int last_error = WSAGetLastError();
	std::cerr << "WSAGetLastError: " << last_error << std::endl;

	throw std::runtime_error(error_message);
	
}

bool ClientSecureConnection::is_socket_valid(SOCKET& socket)
{
	if (socket == INVALID_SOCKET)
	{
		report_error("Socket is invalid!");
		return false;
	}
	return true;
}

ClientSecureConnection::ClientSecureConnection(const std::string& ip_address, unsigned short int port) : m_ip_address(ip_address), m_port(port)
{
	//Loading and Checking input IP and port
	std::cout << "[ClientSecureConnection] Initializing ClientSecureConnection with server info" << std::endl;
    serverAddress.sin_family = AF_INET; 
	serverAddress.sin_port = htons(m_port); 

    //addr is loaded into serverAddress here
	int return_value = inet_pton(AF_INET, ip_address.c_str(), &serverAddress.sin_addr.s_addr);
	if ( return_value == -1)
	{
		report_error("Numeric conversion of the IP Address has failed.");
	}
	else if (return_value == 0)
	{
		//std::cout << "IP notation is not a valid IPv4 or IPv6 dotted-decimal address string." << std::endl;
		report_error("IP notation is not a valid IPv4 or IPv6 dotted-decimal address string.");
	}
    std::cout << "[ClientSecureConnection] Initialization Success - IP: " << m_ip_address << " Port: " << std::to_string(port) << std::endl;

	/*
	//Creating and Binding Socket
	std::cout << "[start] Creating & Binding socket to serverAddress " << std::endl;
	if (WSAStartup(MAKEWORD(2, 0), &m_wsa_data) != 0){
		report_error("[start] WSAStartup failed!");
	}
	else {
		sockfd = socket(AF_INET, SOCK_DGRAM, 0);
		if (is_socket_valid(sockfd)) {
			if (bind(sockfd, (sockaddr*)&serverAddress, sizeof(serverAddress)) == SOCKET_ERROR)
			{
				report_error("Socket binding failed!");
			}
		}
	}
	std::cout << "[start] Binding Successful " << std::endl;
	*/

}



void ClientSecureConnection::secureConnect(){
	if(connect(sockfd, (struct sockaddr *)&serverAddress, sizeof(serverAddress)) < 0){
		std::cout << "[secureConnect] Failed to Connect to Server, Attempting to Reconnect..." << std::endl;
        int i;
        do{
           i = connect(sockfd, (struct sockaddr *)&serverAddress, sizeof(serverAddress));
        }while(i<0);
    }
	std::cout << "[secureConnect] Connected to Server" << std::endl;
}


