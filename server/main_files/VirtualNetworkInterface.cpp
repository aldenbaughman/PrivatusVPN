#include "../header_files/VirtualNetworkInterface.h"

void report_error(const std::string& error_message)
{
	throw std::runtime_error(error_message);
}

void vni_class_print(std::string classname, std::string str){
    std::string classname_tag = "[" + classname + "] ";
    std::cout << classname_tag << str << std::endl;
}

VirtualNetworkInterface::VirtualNetworkInterface(std::string tunIpAddr) : m_tunIpAddr(tunIpAddr) {
     m_tunfd = open("/dev/net/tun", O_RDWR);
    if (m_tunfd < 0) {
        perror("Failed to open /dev/net/tun");
    }

    vni_class_print("VirtualNetworkInterface", "m_tunfd file descriptor: " + std::to_string(m_tunfd));

    memset(&m_ifr, 0, sizeof(m_ifr)); 
}

void VirtualNetworkInterface::start(){
    
    //setting interface flags to recieve ip packets with no extra padding
    m_ifr.ifr_flags = IFF_TUN | IFF_NO_PI; 
    //naming the interface

    // Name
    strncpy(m_ifr.ifr_name, "VPN", IFNAMSIZ); 

    vni_class_print("start", "m_tunfd file descriptor: " + std::to_string(m_tunfd));

    //input output Control, initializing the filedescriptor
    if (ioctl(m_tunfd, TUNSETIFF, (void *)&m_ifr) < 0) {
        close(m_tunfd);
        perror("ioctl(TUNSETIFF)");
        //report_error("Initializing tun fd");
    }

    // Creating Socket inorder to use ioctl ip functions
    int sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock_fd == 0){
        perror("Failed to create socket file description in start()");
        report_error("Failed to create socket");
    }

    struct sockaddr_in* addr = (struct sockaddr_in*)&m_ifr.ifr_addr;
    addr->sin_family = AF_INET;
    inet_pton(AF_INET, m_tunIpAddr.c_str(), &addr->sin_addr);

    // Ip
    if (ioctl(sock_fd, SIOCSIFADDR, &m_ifr) < 0) {
        close(sock_fd);
        perror("Error setting IP");
        report_error("Error setting IP");
    }
    
    // Mask 
    //                  mask for /24
    inet_pton(AF_INET, "255.255.255.0", &addr->sin_addr);
    if (ioctl(sock_fd, SIOCSIFNETMASK, &m_ifr) < 0) {
        perror("Error setting Netmask");
        report_error("Error setting Netmask");
    }

    // MTU
    m_ifr.ifr_mtu = 1400;
    if (ioctl(sock_fd, SIOCSIFMTU, &m_ifr) < 0) {
        perror("Error setting MTU");
        report_error("Error setting MTU");
    }

    // Starting Tun
    if (ioctl(sock_fd, SIOCGIFFLAGS, &m_ifr) >= 0) {
        m_ifr.ifr_flags |= (IFF_UP | IFF_RUNNING); // Add UP and RUNNING bits
        if (ioctl(sock_fd, SIOCSIFFLAGS, &m_ifr) < 0) {
            perror("Error setting Link UP");
            report_error("Error setting Link UP");
        }
    }

    close(sock_fd);
    
    std::cout << "[VirtualNetworkInterface] Initialized with tun0 at 10.8.0.1" << std::endl;
}

int VirtualNetworkInterface::getTunFd(){
    return m_tunfd;
}

int VirtualNetworkInterface::tunRead(uint8_t* readBuffer, int bufferSize){
    int bytes_read = read(m_tunfd, readBuffer, bufferSize);
    return bytes_read;
} 

int VirtualNetworkInterface::tunWrite(uint8_t* packet, int packetSize){
   int bytes_written = write(m_tunfd, packet, packetSize);
   return bytes_written;
}

void VirtualNetworkInterface::ping_test(){
    char readBuffer[8000];
    int bytesRead;
    
    std::cout << "[ping_test] starting ping test" << std::endl;
    while(1){
        bytesRead = read(m_tunfd, readBuffer, sizeof(readBuffer));
        std::cout << "[ping_test] Bytes Recieved: " << std::to_string(bytesRead) << std::endl;
    }
}
