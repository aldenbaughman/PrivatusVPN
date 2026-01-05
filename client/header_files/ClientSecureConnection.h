
#pragma once


#include <WS2tcpip.h>
#include <openssl/ssl.h>   
#include <openssl/err.h>   
#include <openssl/bio.h>   

#include <iostream>
#include <stdexcept>
#include <string>

class ClientSecureConnection
{
private:
	SOCKET m_sockfd {INVALID_SOCKET};
	sockaddr_in m_serverAddress;
	static const unsigned int bufferSize{1024};

	std::string m_ip_address{};
	unsigned short m_port{};

	WSADATA m_wsa_data{};

	SSL_CTX* m_ssl_ctx;

	SSL* m_ssl;

	static void report_error(const std::string& message);

public:
	ClientSecureConnection(const std::string& ip_address, unsigned short int port);
	void connect();
	int send(const BYTE*, int);
	int recv(BYTE* byteBuffer, int bufferSize);

	void udptest();
	bool is_socket_valid(SOCKET& socket);
	
};


