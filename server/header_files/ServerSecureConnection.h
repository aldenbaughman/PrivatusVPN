#ifndef SERVER_CONNECTION
#define SERVER_CONNECTION

#include <cstddef>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include "PacketEnums.h"

class ServerSecureConnection
{
private:
	int m_sockfd;
	sockaddr_in m_serverAddress;
	static const unsigned int bufferSize{1024};

	std::string m_ip_address{};
	unsigned short m_port{};

	SSL_CTX* m_ssl_ctx;
	SSL* m_ssl;
	unsigned char m_cookie_secret[32];

	static void report_error(const std::string& message);

	static void packet_print(uint8_t* Packet, int PacketSize);
	
	EVP_PKEY* generateKey();
	X509* generateX509(EVP_PKEY* pkey, const std::string& ip_address);
	static int generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len);
	static int verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len);

public:
	ServerSecureConnection(const std::string& ip_address, short unsigned int port);
	
	void start();
	int recv(uint8_t* packetBuffer, int bufferSize);
	int send(uint8_t* packet, int packetSize);

	void wintunReadTest();
	void sslSendRecvTest();
	void udptest();

	
};

#endif 
