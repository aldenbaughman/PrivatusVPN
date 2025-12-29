#ifndef SERVER_CONNECTION
#define SERVER_CONNECTION

#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


class ServerSecureConnection
{
private:
	int sockfd;
	sockaddr_in serverAddress;
	static const unsigned int bufferSize{1024};

	std::string m_ip_address{};
	unsigned short m_port{};

	static void report_error(const std::string& message);

public:
	ServerSecureConnection(const std::string& ip_address, unsigned short int port);

	void start();

	
};

#endif 
