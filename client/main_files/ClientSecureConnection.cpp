#include "../header_files/ClientSecureConnection.h"
#include <iostream>
#include <stdexcept>

void printWindowsServerAddress(const sockaddr_in& addr) {
    // Buffer to hold the human-readable IP string
    // INET_ADDRSTRLEN is 16 (enough for "xxx.xxx.xxx.xxx")
    char ipStr[INET_ADDRSTRLEN] = {0};

    // 1. Convert binary IP to String
    // Note: We cast to PVOID for the second argument to satisfy Windows API
    if (InetNtopA(AF_INET, (PVOID)&addr.sin_addr, ipStr, sizeof(ipStr)) == NULL) {
        std::cerr << "[Debug] InetNtopA failed with error: " << WSAGetLastError() << std::endl;
        return;
    }

    // 2. Convert Port from Network Byte Order to Host Byte Order
    unsigned short hostPort = ntohs(addr.sin_port);

    // 3. Print the results
    std::cout << "\n========== Windows Socket Debug ==========" << std::endl;
    std::cout << "  Family:         " << (addr.sin_family == AF_INET ? "AF_INET (IPv4)" : "Unknown") << std::endl;
    std::cout << "  IP (String):    " << ipStr << std::endl;
    std::cout << "  Port (Host):    " << hostPort << std::endl;
    std::cout << "  Port (Network): " << addr.sin_port << " (Hex: 0x" << std::hex << addr.sin_port << std::dec << ")" << std::endl;
    std::cout << "==========================================\n" << std::endl;
}

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
	if (WSAStartup(MAKEWORD(2, 2), &m_wsa_data) != 0) {
        report_error("WSAStartup failed");
    }
	
	//Loading and Checking input IP and port
	std::cout << "[ClientSecureConnection] Initializing ClientSecureConnection with server info" << std::endl;
    
	// Creating socket file descriptor 
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("socket");
		report_error("Failed to make socket");
	}
	//std::cout << "[ClientSecureConnection] Created Socket: " << sockfd << std::endl;

	
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
    std::cout << "[ClientSecureConnection] Initialization Success - IP: " << m_ip_address << " | Port: " << std::to_string(port) << " | Socket: " << sockfd << std::endl;

}



void ClientSecureConnection::secureConnect(){
	//char pkt[bufferSize] = "Hello There";
	const char *pkt = "LETS GOOOOOOOOOOOOOOOOOOOOOOOOOOO";

	//printWindowsServerAddress(serverAddress);

	std::cout << "[secureConnect] Sending pkt to server" << std::endl;
	int send_error;
	 if ((send_error = sendto(sockfd, (const char *)pkt, strlen(pkt),
			0, (const struct sockaddr *) &serverAddress, sizeof(serverAddress))) < 0){
				perror("sendto");
				std::cout << "[secureConnect] Failed to send pkt: " << std::to_string(send_error) << std::endl;
			}
	
}


