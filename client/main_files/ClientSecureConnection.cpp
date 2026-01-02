#include "../header_files/ClientSecureConnection.h"

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

std::string get_ssl_error_string(int error) {
    switch (error) {
        case SSL_ERROR_NONE:             return "SSL_ERROR_NONE";
        case SSL_ERROR_ZERO_RETURN:      return "SSL_ERROR_ZERO_RETURN (Connection closed)";
        case SSL_ERROR_WANT_READ:        return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:       return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_CONNECT:     return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:      return "SSL_ERROR_WANT_ACCEPT";
        case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL:          return "SSL_ERROR_SYSCALL (Check errno)";
        case SSL_ERROR_SSL:              return "SSL_ERROR_SSL (Protocol error)";
        default:                         return "UNKNOWN_SSL_ERROR";
    }
}

void ClientSecureConnection::report_error(const std::string& error_message)
{
	int last_error = WSAGetLastError();
	std::cerr << "WSAGetLastError: " << last_error << std::endl;
	
	int err = errno;
	std::cerr << "System Error: " << strerror(err) << " (Code: " << err << ")" << std::endl;
	
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
	std::cout << "[ClientSecureConnection] WSAStartup Complete" << std::endl;
    
	// Creating socket file descriptor 
    if ((m_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
		perror("socket");
		report_error("Failed to make socket");
	}
	
	m_serverAddress.sin_family = AF_INET; 
	m_serverAddress.sin_port = htons(m_port); 

    //addr is loaded into serverAddress here
	int return_value = inet_pton(AF_INET, ip_address.c_str(), &m_serverAddress.sin_addr);
	if ( return_value == -1){
		report_error("Numeric conversion of the IP Address has failed.");
	}
	else if (return_value == 0){
		report_error("IP notation is not a valid IPv4 or IPv6 dotted-decimal address string.");
	}
    std::cout << "[ClientSecureConnection] Initialization Success - IP: " << m_ip_address << " | Port: " << std::to_string(port) << " | Socket: " << m_sockfd << std::endl;

	//Openssl Context
	const SSL_METHOD* method = DTLS_client_method();
	SSL_CTX* ctx = SSL_CTX_new(method); 
	m_ssl_ctx = ctx;

	SSL_CTX_set_options(m_ssl_ctx, SSL_OP_NO_QUERY_MTU);
	SSL_CTX_set_verify(m_ssl_ctx, SSL_VERIFY_NONE, NULL);
	
}

void ClientSecureConnection::secureConnect(){
	SSL* ssl = SSL_new(m_ssl_ctx);

	BIO* bio = BIO_new_dgram(m_sockfd, BIO_NOCLOSE);

	SSL_set_options(ssl, SSL_OP_NO_QUERY_MTU);
	SSL_set_mtu(ssl, 1000);

	BIO_ctrl(bio, BIO_CTRL_DGRAM_SET_PEER, 0, &m_serverAddress);

	SSL_set_bio(ssl, bio, bio);
	SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);

	// Set the BIO to non-blocking mode
	BIO_set_nbio(SSL_get_rbio(ssl), 1);

	//set the initial timeout to 1 second in BIO_ctrl
	long timeout_ms = 1000; 
	BIO_ctrl(SSL_get_rbio(ssl), BIO_CTRL_DGRAM_SET_RECV_TIMEOUT, 0, &timeout_ms);

	int result;
	struct timeval timeout;
	//try connecting to server 
	//if it fails 
	while ((result = SSL_connect(ssl)) <= 0) {
		int error = SSL_get_error(ssl, result);

		if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE ) {
			int err = errno;
			std::cerr << "System Error: " << strerror(err) << " (Code: " << err << ")" << std::endl;
			std::cout << get_ssl_error_string(error) << std::endl;
			// get_timeout keeps track of the last packet sent and 
			// tells if it is ready to send another
			if (DTLSv1_get_timeout(ssl, &timeout)) {
				fd_set fdread;
				FD_ZERO(&fdread);
				FD_SET(m_sockfd, &fdread);
				//select waits for a resposne on the socekt
				select(m_sockfd + 1, &fdread, NULL, NULL, &timeout);
			}
	
			// Tell OpenSSL to handle any expired timers/retransmissions
			DTLSv1_handle_timeout(ssl);
		}
		else {
			report_error(get_ssl_error_string(error));
		}
	}

	std::cout << "[secureConnect] Client connect to server, waiting for message from server" << std::endl;

	char buffer[4096];
	int bytes_received = SSL_read(ssl, buffer, sizeof(buffer));
	if (bytes_received > 0) {
		std::cout << "[secureConnect] Message from server: " << buffer << std::endl;
	} else {
		std::cout << "[secureConnect] Possible error, packet from server recieved with no bytes" << std::endl;
	}

	const char* msg = "Thank you glad to be here!";
    int bytes_sent = SSL_write(ssl, msg, strlen(msg));
    if (bytes_sent <= 0) {
        report_error("Packet failed to send");
    }
}

void ClientSecureConnection::udptest(){
	//char pkt[bufferSize] = "Hello There";
	const char *pkt = "LETS GOOOOOOOOOOOOOOOOOOOOOOOOOOO";

	//printWindowsServerAddress(serverAddress);

	std::cout << "[udptest] Sending pkt to server" << std::endl;
	int send_error;
	if ((send_error = sendto(m_sockfd, (const char *)pkt, strlen(pkt),
		0, (const struct sockaddr *) &m_serverAddress, sizeof(m_serverAddress))) < 0){
			perror("sendto");
			std::cout << "[udptest] Failed to send pkt: " << std::to_string(send_error) << std::endl;
		}

	char client_pkt[bufferSize];

    int MAXLINE = 1024;
	socklen_t lens = sizeof(m_serverAddress);
	
	int n = recvfrom(m_sockfd, (char *)client_pkt, MAXLINE,  
                0, ( struct sockaddr *) &m_serverAddress, 
                &lens); 
	if (n <= 0){
		perror("recvfrom");
		report_error("Failed to recieve packet");
	}
    client_pkt[n] = '\0'; 
    printf("[udptest] Server Echo: %s\n", client_pkt); 
	
}


