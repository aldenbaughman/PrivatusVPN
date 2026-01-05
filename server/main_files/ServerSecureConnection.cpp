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

void class_print(std::string classname, std::string str){
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

void ServerSecureConnection::packet_print(uint8_t* Packet, int PacketSize){
    IPVersion ver = static_cast<IPVersion>(Packet[0] >> 4);

    switch (ver){
        case IPVersion::IPv4:
            class_print("packet_print", 
                            "IP type: " 
                            + IPVersionToString(ver) 
                            + " | Protocol Type: " 
                            + IPProtocolToString(static_cast<IPProtocol>(Packet[9])) 
                            + " | Size: " 
                            + std::to_string(PacketSize));
            break;
        case IPVersion::IPv6:
            class_print("packet_print", "IP type: " 
                            + IPVersionToString(ver) 
                            + " | Protocol Type: " 
                            + IPProtocolToString(static_cast<IPProtocol>(Packet[6]))
                            + " | Size: " 
                            + std::to_string(PacketSize));
            break;
        default:
            class_print("packet_print", "packet has undefined format");
    }
}

std::string get_ssl_error_string(int error) {
    switch (error) {
        case SSL_ERROR_NONE:             return "SSL_ERROR_NONE";
        case SSL_ERROR_ZERO_RETURN:      return "SSL_ERROR_ZERO_RETURN";
        case SSL_ERROR_WANT_READ:        return "SSL_ERROR_WANT_READ";
        case SSL_ERROR_WANT_WRITE:       return "SSL_ERROR_WANT_WRITE";
        case SSL_ERROR_WANT_CONNECT:     return "SSL_ERROR_WANT_CONNECT";
        case SSL_ERROR_WANT_ACCEPT:      return "SSL_ERROR_WANT_ACCEPT";
        case SSL_ERROR_WANT_X509_LOOKUP: return "SSL_ERROR_WANT_X509_LOOKUP";
        case SSL_ERROR_SYSCALL:          return "SSL_ERROR_SYSCALL";
        case SSL_ERROR_SSL:              return "SSL_ERROR_SSL";
        default:                         return "UNKNOWN_ERROR";
    }
}

void ServerSecureConnection::report_error(const std::string& error_message){
	int err = errno;
	std::cerr << "System Error: " << strerror(err) << " (Code: " << err << ")" << std::endl;
    throw std::runtime_error(error_message);
}

EVP_PKEY* ServerSecureConnection::generateKey(){
    //Openssl malloc specifically for PKEY
    EVP_PKEY* pkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_keygen(ctx, &pkey);
    
    EVP_PKEY_CTX_free(ctx);
    return pkey; 
}

X509* ServerSecureConnection::generateX509(EVP_PKEY* pkey, const std::string& ip_address){
    //Openssl Malloc specifically for x509
    X509* x509 = X509_new();

    X509_set_version(x509, 2);

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);

    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);

    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (unsigned char*)"US", -1, -1, 0);
    //                                                    black magic to turn input ip into type for openssl
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(ip_address.c_str()), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // Sign the certificate with the private key
    X509_sign(x509, pkey, EVP_sha256());

    return x509;
}

//must be static to be input to Openssl function
int ServerSecureConnection::generate_cookie(SSL *ssl, unsigned char *cookie, unsigned int *cookie_len) {
    BIO_ADDR *peer = BIO_ADDR_new();
    
    //Retrieve the ServerSecureConnection instance to access the m_cooki_secret for cookie generate
    SSL_CTX* ctx = SSL_get_SSL_CTX(ssl);
    ServerSecureConnection* instance = static_cast<ServerSecureConnection*>(SSL_CTX_get_app_data(ctx));
    
    // Get client's address
    if (BIO_dgram_get_peer(SSL_get_rbio(ssl), peer) <= 0) {
        BIO_ADDR_free(peer);
        return 0;
    }

    // Get raw bytes of client's address as message
    int peer_len = BIO_ADDR_rawaddress(peer, NULL, NULL);
    unsigned char peer_data[32]; 
    BIO_ADDR_rawaddress(peer, peer_data, (size_t*)&peer_len);

    // Hash client address with our cookie secret
    unsigned int md_len;
    HMAC(EVP_sha256(), 
         instance->m_cookie_secret, sizeof(m_cookie_secret), 
         peer_data, peer_len,                      
         cookie, &md_len);                        

    *cookie_len = md_len;

    BIO_ADDR_free(peer);
    return 1;
}

int ServerSecureConnection::verify_cookie(SSL *ssl, const unsigned char *cookie, unsigned int cookie_len) {
    unsigned char expected_cookie[EVP_MAX_MD_SIZE];
    unsigned int expected_len;

    if (generate_cookie(ssl, expected_cookie, &expected_len) &&
        cookie_len == expected_len &&
        memcmp(cookie, expected_cookie, cookie_len) == 0) {
        return 1; 
    }

    return 0; // Verification failed
}


ServerSecureConnection::ServerSecureConnection(const std::string& ip_address, short unsigned int port) : m_ip_address(ip_address), m_port(port){

	//Loading and Checking input IP and port
	std::cout << "[ServerSecureConnection] Initializing ServerSecureConnection with server info" << std::endl;
    m_serverAddress.sin_family = AF_INET; 
	m_serverAddress.sin_port = htons(m_port); 

    //addr is loaded into serverAddress here
	int return_value = inet_pton(AF_INET, ip_address.c_str() , &m_serverAddress.sin_addr);
	if ( return_value == -1)
	{
		report_error("Numeric conversion of the IP Address has failed.");
	}
	else if (return_value == 0)
	{
		report_error("IP notation is not a valid IPv4 or IPv6 dotted-decimal address string.");
	}

    if ((m_sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0){
        perror("socket");
        report_error("[ServerSecureConnection] Failed to create socket");
    };
    
    //idk what this does but...
    int optval = 1;
	setsockopt(m_sockfd, SOL_SOCKET, SO_REUSEADDR, (void *)&optval, sizeof(optval));

    if ((bind(m_sockfd, (struct sockaddr *)&m_serverAddress, sizeof(m_serverAddress))) <0) {
        perror("bind");
        report_error("[ServerSecureConnection] Failed to bind socket and address");
    };
    std::cout << "[ServerSecureConnection] Initialization Success - IP: " << ip_address.c_str() << " | Port: " << std::to_string(port) << " | Socket: " << std::to_string(m_sockfd) << std::endl;
	
    //generating random cookie secret for cookies later used to verify client is not 
    //DDOSing the server
    if (RAND_bytes(m_cookie_secret, sizeof(m_cookie_secret)) <= 0) {
        report_error("Failed to generate random seed");
    }

    //OpenSSL
    OPENSSL_init_ssl(0, NULL);
	std::cout << "[ServerSecureConnection] OpenSSL Version: " << OpenSSL_version(OPENSSL_VERSION) << std::endl;


    const SSL_METHOD* method = DTLS_server_method();
    SSL_CTX* ctx = SSL_CTX_new(method);

    //setting ssl context to method context
    m_ssl_ctx = ctx;

    SSL_CTX_set_app_data(m_ssl_ctx, this);
    SSL_CTX_set_options(m_ssl_ctx, SSL_OP_COOKIE_EXCHANGE);
    SSL_CTX_set_read_ahead(m_ssl_ctx, 1);
    
    EVP_PKEY* pkey = generateKey();
    X509* cert = generateX509(pkey, ip_address);

    SSL_CTX_use_certificate(m_ssl_ctx, cert);
    SSL_CTX_use_PrivateKey(m_ssl_ctx, pkey);

    if (!SSL_CTX_check_private_key(m_ssl_ctx)) {
        report_error("Generated Certificate and Private Key do not match");
    }

    //adding functions to generate and verify cookies into ssl context
    SSL_CTX_set_cookie_generate_cb(m_ssl_ctx, &generate_cookie);
    SSL_CTX_set_cookie_verify_cb(m_ssl_ctx, &verify_cookie);


    //these are already stored in m_ssl_ctx and can be freed?
    EVP_PKEY_free(pkey);
    X509_free(cert);
}

void ServerSecureConnection::start(){
    BIO* bio = BIO_new_dgram(m_sockfd, BIO_NOCLOSE);
    m_ssl = SSL_new(m_ssl_ctx);
    SSL_set_bio(m_ssl, bio, bio);

    std::cout << "[start] Waiting for client to connect..." << std::endl;
    BIO_ADDR *client_addr = BIO_ADDR_new();
    //waits until the client has been verfied with a cookie
    //INEFFICENT, WHILE BLOCKING CONSUMES 100% OF CPU
    //while (DTLSv1_listen(ssl, (BIO_ADDR *)&client_addr) <= 0);

    while (true) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(m_sockfd, &rfds);

        // Wait here (sleep) until data arrives
        if (select(m_sockfd + 1, &rfds, NULL, NULL, NULL) > 0) {
            int listen_res = DTLSv1_listen(m_ssl, client_addr);
            if (listen_res > 0) break; // Valid cookie received!
        }
    }

    std::cout << "[start] Client Attempting to connect: " << BIO_ADDR_hostname_string(client_addr, 1) << ":" << BIO_ADDR_service_string(client_addr, 1) << std::endl;

    //listen consumes socket, this tells socket to send to this addr
    BIO_ctrl(SSL_get_rbio(m_ssl), BIO_CTRL_DGRAM_SET_PEER, 0, &client_addr);

    int res;
    while ((res = SSL_accept(m_ssl)) <= 0) {
        int error = SSL_get_error(m_ssl, res);
        
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            // Wait for the next handshake packet
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(m_sockfd, &rfds);
            
            struct timeval timeout;
            if (DTLSv1_get_timeout(m_ssl, &timeout)) {
                select(m_sockfd + 1, &rfds, NULL, NULL, &timeout);
            } else {
                select(m_sockfd + 1, &rfds, NULL, NULL, NULL);
            }
            DTLSv1_handle_timeout(m_ssl);
        } else {
            // A real error occurred
            report_error("Handshake failed: " + get_ssl_error_string(error));
        }
    }
}

int ServerSecureConnection::send(uint8_t* packet, int packetSize){
    int bytes_sent = SSL_write(m_ssl, (const void *)packet, packetSize);
    if (bytes_sent <= 0) {
        report_error("Packet failed to send");
    }

	return bytes_sent;
}

int ServerSecureConnection::recv(uint8_t* packetBuffer, int bufferSize){
    int bytes_received = SSL_read(m_ssl, packetBuffer, bufferSize);
	if (bytes_received > 0) {
		return bytes_received;
	} else {
		std::cout << "[secureConnect] Possible error, packet from server recieved with no bytes" << std::endl;
		return 0;
	}
}



void ServerSecureConnection::wintunReadTest(){
    std::cout << "[wintunReadTest] Starting wintun Read test" << std::endl;
    uint8_t packetBuffer[4096];
    int bytes_received;
    while(1){
        bytes_received = SSL_read(m_ssl, (uint8_t*)packetBuffer, sizeof(packetBuffer));

        //printf("[DEBUG] Raw Hex: %02x %02x %02x %02x\n", 
                    //packetBuffer[0], packetBuffer[1], packetBuffer[2], packetBuffer[3]);

        //std::cout << "[wintunReadTest] Recieved " + std::to_string(bytes_received) + " bytes" << std::endl;
        //std::cout << "[wintunReadTest] Packet contents: " + packetBuffer << std::endl;
        if (bytes_received > 0) {
            packet_print(packetBuffer, bytes_received);
        } else {
            std::cout << "[secureConnect] Possible error, packet from client recieved with no bytes" << std::endl;
        }
    }
}

void ServerSecureConnection::sslSendRecvTest(){
    std::cout << "[start] Accepted Client and sending message" << std::endl;

    const char* msg = "Welcome to the Server!!!!";
    int bytes_sent = SSL_write(m_ssl, msg, strlen(msg));
    if (bytes_sent <= 0) {
        // Check SSL_get_error to see if the connection dropped
    }

    char buffer[4096];
	int bytes_received = SSL_read(m_ssl, buffer, sizeof(buffer));
	if (bytes_received > 0) {
		std::cout << "[secureConnect] Message from client: " << buffer << std::endl;
	} else {
		std::cout << "[secureConnect] Possible error, packet from client recieved with no bytes" << std::endl;
	}
}

void ServerSecureConnection::udptest(){
    std::cout << "[start] Waiting for Datagram from socket" << std::endl;

    char buffer[1024];
    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);
    
    while (1){
        int received = recvfrom(m_sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&client_addr, &addr_len);
        
        if (received > 0) {
            int sent = sendto(m_sockfd, buffer, received, 0, (struct sockaddr*)&client_addr, addr_len);
            std::cout << "Sent back " << sent << " bytes." << std::endl;
        }
        else {
            report_error("recieved empty pkt");
        }
    }
}
