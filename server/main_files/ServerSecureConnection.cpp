#include <iostream>
#include <stdexcept>
#include "../header_files/ServerSecureConnection.h"

void printServerAddress(const sockaddr_in& addr) {
    char ipStr[INET_ADDRSTRLEN]; // Buffer to hold the IP string

    // 1. Convert the binary IP back to a string
    if (inet_ntop(AF_INET, &(addr.sin_addr), ipStr, INET_ADDRSTRLEN) == nullptr) {
        std::cerr << "Failed to convert IP for printing" << std::endl;
        return;
    }

    // 2. Convert the Port from Network Byte Order back to Host Byte Order
    uint16_t port = ntohs(addr.sin_port);

    // 3. Output the details
    std::cout << "--- Server Address Info ---" << std::endl;
    std::cout << "Family: " << (addr.sin_family == AF_INET ? "IPv4" : "Other") << std::endl;
    std::cout << "IP Address: " << ipStr << std::endl;
    std::cout << "Port (Network Order): " << addr.sin_port << std::endl;
    std::cout << "Port (Host Order):    " << port << std::endl;
    std::cout << "---------------------------" << std::endl;
}

void ServerSecureConnection::report_error(const std::string& error_message)
{
	throw std::runtime_error(error_message);
}


ServerSecureConnection::ServerSecureConnection(const std::string& ip_address, unsigned short int port) : m_ip_address(ip_address), m_port(port)
{
	//Loading and Checking input IP and port
	std::cout << "[ServerSecureConnection] Initializing ServerSecureConnection with server info" << std::endl;
    serverAddress.sin_family = AF_INET; 
	serverAddress.sin_port = htons(m_port); 

    //addr is loaded into serverAddress here
    //ip_address.c_str()
	int return_value = inet_pton(AF_INET, ip_address.c_str() , &serverAddress.sin_addr.s_addr);
	if ( return_value == -1)
	{
		report_error("Numeric conversion of the IP Address has failed.");
	}
	else if (return_value == 0)
	{
		//std::cout << "IP notation is not a valid IPv4 or IPv6 dotted-decimal address string." << std::endl;
		report_error("IP notation is not a valid IPv4 or IPv6 dotted-decimal address string.");
	}
    std::cout << "[ServerSecureConnection] Initialization Success - IP: " << ip_address.c_str() << " Port: " << std::to_string(port) << std::endl;


	//Creating and Binding Socket
    /*
    
    if (is_socket_valid(sockfd)) {
        
    }
	*/
    if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("socket");
        report_error("[ServerSecureConnection] Failed to create socket");
    };
    
    //idk what this does but...
    int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(optval));


    std::cout << "[ServerSecureConnection] Created Socket: " << std::to_string(sockfd) << std::endl;
    if ((bind(sockfd, (struct sockaddr *)&serverAddress, sizeof(serverAddress))) <0) {
        perror("bind");
        report_error("[ServerSecureConnection] Failed to bind socket and address");
    };
	std::cout << "[ServerSecureConnection] Binding Successful " << std::endl;
	
}

void ServerSecureConnection::start(){
    //listen unessary for UDP 

    struct sockaddr_in cliaddr;
    socklen_t len = sizeof(cliaddr);
    socklen_t lens = sizeof(serverAddress);

    char client_pkt[bufferSize];

    int MAXLINE = 1024;

    std::cout << "[start] Waiting for Datagram from socket" << std::endl;
    
    //printServerAddress(serverAddress);
    while(1){
    int n = recvfrom(sockfd, (char *)client_pkt, MAXLINE,  
                MSG_WAITALL, ( struct sockaddr *) &serverAddress, 
                &lens); 

    client_pkt[n] = '\0'; 
    printf("[start] Recieved Datagram: %s\n", client_pkt); }

    std::cout << "[start] Recieved Datagram from: " << cliaddr.sin_addr.s_addr << std::endl;

}
