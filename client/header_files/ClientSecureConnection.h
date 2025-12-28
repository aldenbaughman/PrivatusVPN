
#ifndef CLIENT_CONNECTION
#define CLIENT_CONNECTION

#include <string>
#include <WS2tcpip.h>

class ClientSecureConnection
{
private:
	SOCKET sockfd {INVALID_SOCKET};
	sockaddr_in serverAddress;
	static const unsigned int bufferSize{1024};

	std::string m_ip_address{};
	unsigned short m_port{};

	WSADATA m_wsa_data{};

	static void report_error(const std::string& message);

public:
	ClientSecureConnection(const std::string& ip_address, unsigned short int port);
	void secureConnect();

	bool is_socket_valid(SOCKET& socket);
	
};




#endif 
