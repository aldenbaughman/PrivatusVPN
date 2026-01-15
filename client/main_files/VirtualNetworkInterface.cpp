#include "../header_files/VirtualNetworkInterface.h"
#include <cstdint>

int max_print_spaces = 0;

WINTUN_CREATE_ADAPTER_FUNC* VirtualNetworkInterface::WintunCreateAdapter = nullptr;
WINTUN_CLOSE_ADAPTER_FUNC* VirtualNetworkInterface::WintunCloseAdapter = nullptr;
WINTUN_OPEN_ADAPTER_FUNC* VirtualNetworkInterface::WintunOpenAdapter = nullptr;
WINTUN_GET_ADAPTER_LUID_FUNC* VirtualNetworkInterface::WintunGetAdapterLUID = nullptr;
WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC* VirtualNetworkInterface::WintunGetRunningDriverVersion = nullptr;
WINTUN_DELETE_DRIVER_FUNC* VirtualNetworkInterface::WintunDeleteDriver = nullptr;
WINTUN_SET_LOGGER_FUNC* VirtualNetworkInterface::WintunSetLogger = nullptr;
WINTUN_START_SESSION_FUNC* VirtualNetworkInterface::WintunStartSession = nullptr;
WINTUN_END_SESSION_FUNC* VirtualNetworkInterface::WintunEndSession = nullptr;
WINTUN_GET_READ_WAIT_EVENT_FUNC* VirtualNetworkInterface::WintunGetReadWaitEvent = nullptr;
WINTUN_RECEIVE_PACKET_FUNC* VirtualNetworkInterface::WintunReceivePacket = nullptr;
WINTUN_RELEASE_RECEIVE_PACKET_FUNC* VirtualNetworkInterface::WintunReleaseReceivePacket = nullptr;
WINTUN_ALLOCATE_SEND_PACKET_FUNC* VirtualNetworkInterface::WintunAllocateSendPacket = nullptr;
WINTUN_SEND_PACKET_FUNC* VirtualNetworkInterface::WintunSendPacket = nullptr;

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

void VirtualNetworkInterface::packet_print(BYTE* Packet, DWORD PacketSize){
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
    }
}

void report_error(const std::string& error_message)
{
	throw std::runtime_error(error_message);
}

HMODULE VirtualNetworkInterface::InitializeWintun(void){
    std::wstring fullPath = L"C:\\Users\\spiri\\OneDrive\\Desktop\\PrivatusVPN\\client\\wintun.dll";
    HMODULE Wintun =LoadLibraryExW(fullPath.c_str(), NULL, LOAD_LIBRARY_SEARCH_APPLICATION_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32);
    if (!Wintun){
        return NULL;
    }
    WintunCreateAdapter = (WINTUN_CREATE_ADAPTER_FUNC*)GetProcAddress(Wintun, "WintunCreateAdapter");
    WintunCloseAdapter = (WINTUN_CLOSE_ADAPTER_FUNC*)GetProcAddress(Wintun, "WintunCloseAdapter");
    WintunOpenAdapter = (WINTUN_OPEN_ADAPTER_FUNC*)GetProcAddress(Wintun, "WintunOpenAdapter");
    WintunGetAdapterLUID = (WINTUN_GET_ADAPTER_LUID_FUNC*)GetProcAddress(Wintun, "WintunGetAdapterLUID");
    WintunGetRunningDriverVersion = (WINTUN_GET_RUNNING_DRIVER_VERSION_FUNC*)GetProcAddress(Wintun, "WintunGetRunningDriverVersion");
    WintunDeleteDriver = (WINTUN_DELETE_DRIVER_FUNC*)GetProcAddress(Wintun, "WintunDeleteDriver");
    WintunSetLogger = (WINTUN_SET_LOGGER_FUNC*)GetProcAddress(Wintun, "WintunSetLogger");
    WintunStartSession = (WINTUN_START_SESSION_FUNC*)GetProcAddress(Wintun, "WintunStartSession");
    WintunEndSession = (WINTUN_END_SESSION_FUNC*)GetProcAddress(Wintun, "WintunEndSession");
    WintunGetReadWaitEvent = (WINTUN_GET_READ_WAIT_EVENT_FUNC*)GetProcAddress(Wintun, "WintunGetReadWaitEvent");
    WintunReceivePacket = (WINTUN_RECEIVE_PACKET_FUNC*)GetProcAddress(Wintun, "WintunReceivePacket");
    WintunReleaseReceivePacket = (WINTUN_RELEASE_RECEIVE_PACKET_FUNC*)GetProcAddress(Wintun, "WintunReleaseReceivePacket");
    WintunAllocateSendPacket = (WINTUN_ALLOCATE_SEND_PACKET_FUNC*)GetProcAddress(Wintun, "WintunAllocateSendPacket");
    WintunSendPacket = (WINTUN_SEND_PACKET_FUNC*)GetProcAddress(Wintun, "WintunSendPacket");
    
    return Wintun;
}

void checkAdapterStatus(NET_IFINDEX index) {
    MIB_IF_ROW2 row;
    ZeroMemory(&row, sizeof(MIB_IF_ROW2));
    row.InterfaceIndex = index;

    if (GetIfEntry2(&row) == NO_ERROR) {
        printf("Adapter Alias: %ws\n", row.Alias);
        printf("Operational Status: ");
        switch (row.OperStatus) {
            case IfOperStatusUp: printf("UP\n"); break;
            case IfOperStatusDown: printf("DOWN\n"); break;
            default: printf("OTHER (%d)\n", row.OperStatus); break;
        }
        printf("Transmit Speed: %llu bps\n", row.TransmitLinkSpeed);
    } else {
        printf("Failed to retrieve adapter info for index %lu\n", index);
    }
}

void CALLBACK MyWintunLogger(WINTUN_LOGGER_LEVEL Level, DWORD64 Timestamp, LPCWSTR Message) {
    const char* levelStr = "INFO";
    switch (Level) {
        case WINTUN_LOG_INFO: levelStr = "INFO"; break;
        case WINTUN_LOG_WARN: levelStr = "WARN"; break;
        case WINTUN_LOG_ERR:  levelStr = "ERROR"; break;
    }

    // Wintun uses Wide Strings (LPCWSTR), so we use wprintf
    fwprintf(stderr, L"[WINTUN-LOGGER %hs] %s\n", levelStr, Message);
}

VirtualNetworkInterface::VirtualNetworkInterface(std::string physicalServerIp, std::string virtualServerIp){
    HMODULE wintunLib = InitializeWintun();
    if ( wintunLib != NULL ){
        class_print("VirtualNetworkInterface", "Loaded Wintun");
    }
    else {
        printf("GetLastError #%d.\n", GetLastError());
        report_error("Failed to load wintun");
    }

    inet_pton(AF_INET, physicalServerIp.c_str(), &m_physicalServerIp);
    class_print("VirtualNetworkInterface", "Server Physical IP: " + physicalServerIp + " - " + std::to_string(m_physicalServerIp));

    inet_pton(AF_INET, virtualServerIp.c_str(), &m_virtualServerIp);
    class_print("VirtualNetworkInterface", "Server Virtual IP: "+ virtualServerIp + " - " + std::to_string(m_virtualServerIp));

    class_print("VirtualNetworkInterface", "Setting up Wintun Logger");
    WintunSetLogger(MyWintunLogger);
}

void GetCurrentNetworkInfo(DWORD& routerIp, DWORD& adapterIndex) {
    
    MIB_IPFORWARDROW bestRoute;
    
    // We ask for the route to a public IP (like Google DNS)
    // to see how the computer currently gets to the internet.
    DWORD destAddr = inet_addr("8.8.8.8");

    if (GetBestRoute(destAddr, 0, &bestRoute) == NO_ERROR) {
        routerIp = bestRoute.dwForwardNextHop;
        adapterIndex = bestRoute.dwForwardIfIndex;

        // Optional: Print it to verify
        struct in_addr ip_addr;
        ip_addr.s_addr = routerIp;
        std::cout << "Original Router: " << inet_ntoa(ip_addr) << std::endl;
        std::cout << "Interface Index: " << adapterIndex << std::endl;
    }
    else { 
        report_error("Failed to get Current Network Info");
    }
}

void addRouteToVPNServer(DWORD serverPublicIp, DWORD localRouterIp, DWORD wifiIndex) {
    
    //use this to find other name then ethernet: netsh interface show interface
    //makes it so computer cannot reroute back to ethernet
    
    system("netsh interface ip set interface \"Ethernet\" metric=100");
    //UNDO WITH: netsh interface ip set interface "Ethernet" metric=automatic
    
    
    //system("route delete 0.0.0.0");

    // First, create a dummy row for the delete operation
    MIB_IPFORWARDROW deleteRow;
    memset(&deleteRow, 0, sizeof(MIB_IPFORWARDROW));
    deleteRow.dwForwardDest = serverPublicIp;
    deleteRow.dwForwardMask = 0xFFFFFFFF;
    deleteRow.dwForwardIfIndex = wifiIndex;

    // Delete it if it exists (ignore the error if it doesn't exist)
    DeleteIpForwardEntry(&deleteRow);
    
    
    
    MIB_IPFORWARDROW route;
    memset(&route, 0, sizeof(MIB_IPFORWARDROW));

    // Destination: The specific public IP of your Linux VPS
    // Since input is already a DWORD (Network Byte Order), assign directly
    route.dwForwardDest = serverPublicIp;
    
    // Mask: 255.255.255.255 (Host route /32)
    // 0xFFFFFFFF means this route applies ONLY to that one specific IP
    route.dwForwardMask = 0xFFFFFFFF;

    // Next Hop: Your local physical router (e.g., 192.168.1.1)
    route.dwForwardNextHop = localRouterIp;

    route.dwForwardIfIndex = wifiIndex;
    
    // Routing Metadata
    route.dwForwardType = MIB_IPROUTE_TYPE_INDIRECT; 
    route.dwForwardProto = MIB_IPPROTO_NETMGMT; // MIB_IPPROTO_NETMGMT

    // THIS VALUE MUST BE 30 (!?!?!?) OR IT DOES NOT WORK
    route.dwForwardMetric1 = 110; // Highest priority (lowest number)
    route.dwForwardMetric2 = (DWORD)-1; // -1 means "not used"
    route.dwForwardMetric3 = (DWORD)-1;
    route.dwForwardMetric4 = (DWORD)-1;
    route.dwForwardAge = 0; //setting it so route doesn't expire
    route.dwForwardPolicy = 0;

    //Fixes 160 error
    DeleteIpForwardEntry(&route);

    DWORD result = CreateIpForwardEntry(&route);
    
    if (result != NO_ERROR) {
        if (result == ERROR_ALREADY_EXISTS) {
            // This is actually fine; it means the route is already there
            class_print("addRouteToVPNServer", "Route to server already exists.");
        } else {
            printf("[Route Error] Result: %lu, Dest: %08X, GW: %08X\n", 
                result, serverPublicIp, localRouterIp);
            printf("Error: %lu\n", result);
            report_error("Failed to add physical route to VPN server.");
        }
    } else {
        class_print("addRouteToVPNServer", "Successfully added exception route for VPN server.");
    }
}

void addTunnelToDefaultGateway(DWORD newGatewayIp, DWORD wintunIndex) {
    class_print("addTunnel", "188");
    MIB_IPFORWARDROW route;
    memset(&route, 0, sizeof(MIB_IPFORWARDROW));
    class_print("addTunnel", "191");

    //This is what changes the default gateway
    route.dwForwardDest = 0;         // 0.0.0.0 (Default)
    route.dwForwardMask = 0;         // 0.0.0.0
    route.dwForwardNextHop = newGatewayIp; // Your Server IP
    route.dwForwardIfIndex = wintunIndex; // Index of your Wintun adapter
    route.dwForwardType = MIB_IPROUTE_TYPE_DIRECT;
    // THIS VALUE MUST BE 3 (!?!?!?) OR IT DOES NOT WORK
    route.dwForwardProto = 3;        // 3 = MIB_IPPROTO_NETMGMT
    route.dwForwardMetric1 = 5;      // Priority (Lower is better)

    route.dwForwardAge = 0;
    route.dwForwardPolicy = 0;

    DeleteIpForwardEntry(&route);
    class_print("addTunnel", "204");
    // Call the API
    DWORD result = CreateIpForwardEntry(&route);
    class_print("addTunnel", "207");

    if (result != NO_ERROR) {
        // If Type 3 failed, try Type 4 as a fallback immediately
        class_print("addTunnel", "trying type indirect");
        route.dwForwardType = 4; 
        result = CreateIpForwardEntry(&route);
    }

    if (result != NO_ERROR) {
        printf("[Tunnel Error] Result: %lu, Gateway: %08X, IF: %lu\n", result, newGatewayIp, wintunIndex);
        std::string txt = "Problem creating Virtual Server Ip Forward Entry: err #";
        report_error(txt.append(std::to_string(result)));
    }

    
}

void VirtualNetworkInterface::start(){
    //Addd actual GUID generator
    GUID SomeFixedGUID2 = { 0xdeadbeef, 0xface, 0x4ace, { 0x9e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } };
    std::string tunName = "VPN";
    std::string ipStr = "10.8.0.2";


    m_adapter = WintunCreateAdapter(L"VPN", L"Wintun", &SomeFixedGUID2);
    if (!m_adapter){
        printf("GetLastError #%d.\n", GetLastError());
        report_error("Failed to create adapter");
    }

    

    m_session = WintunStartSession(m_adapter, 0x400000);
    if (!m_session)
    {
        printf("GetLastError #%d.\n", GetLastError());
        report_error("Failed to create wintun session");
    }
    
    class_print("VirtualNetworkInterface", "Wintun Create Adapter and session Initialized");
    
    MIB_UNICASTIPADDRESS_ROW AddressRow;
    InitializeUnicastIpAddressEntry(&AddressRow);
    WintunGetAdapterLUID(m_adapter, &AddressRow.InterfaceLuid);

    AddressRow.Address.Ipv4.sin_family = AF_INET;
    //AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (8 << 16) | (0 << 8) | 2); /* 10.0.0.1*/
    if (inet_pton(AF_INET, ipStr.c_str(), &AddressRow.Address.Ipv4.sin_addr) != 1){
        report_error("Failed to Convert ip string in wintun start");
    }
    AddressRow.OnLinkPrefixLength = 24; 
    AddressRow.DadState = IpDadStatePreferred;

    //should fix issue of system checking for duplicate ips
    AddressRow.SkipAsSource = FALSE; 

    //nuclear optiojn for dad tenative stuff
    std::string cmd = "netsh interface ipv4 set interface \"" + tunName + "\" dadtransmits=0";
    system(cmd.c_str());

    // Try setting this to 0 to make it permanent/immediate
    AddressRow.ValidLifetime = 0xffffffff;
    AddressRow.PreferredLifetime = 0xffffffff;

    DWORD LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS){
        report_error("Failed to create Ip Address Entry, last error: " + LastError);
    }
    class_print("start", "Created Ip Address Entry");

    //waiting for some stupid ip to be "ready"
    bool ready = false;
    for (int i = 0; i < 20; i++) { // Try for 2 seconds (20 * 100ms)
        MIB_UNICASTIPADDRESS_ROW row;
        InitializeUnicastIpAddressEntry(&row);
        row.InterfaceLuid = AddressRow.InterfaceLuid;
        row.Address = AddressRow.Address;

        if (GetUnicastIpAddressEntry(&row) == NO_ERROR) {
            if (row.DadState == IpDadStatePreferred) {
                class_print("start", "IP Address is now Preferred (Ready)");
                ready = true;
                break;
            }
        }
        Sleep(500);
    }

    if (!ready) {
        report_error("IP Address stayed Tentative for too long.");
    }

    

    char ipString[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(AddressRow.Address.Ipv4.sin_addr), ipString, INET_ADDRSTRLEN)) {
        std::string txt = "Created Session with Address Row: ";
        class_print("start", (txt.append(ipString)));
    } else {
        std::cerr << "Failed to convert IP address. Error: " << WSAGetLastError() << std::endl;
    }

    DWORD routerIp, wifiIndex;
    GetCurrentNetworkInfo(routerIp, wifiIndex);

    NET_LUID luid;
    NET_IFINDEX wintunIndex = 0;
    WintunGetAdapterLUID(m_adapter, &luid);
    ConvertInterfaceLuidToIndex(&luid, &wintunIndex);

    addRouteToVPNServer(m_physicalServerIp, routerIp, wifiIndex);

    addTunnelToDefaultGateway(m_virtualServerIp, wintunIndex);

    //allows vpn to do dns searches
    std::string dnsCmd = "netsh interface ipv4 add dnsserver \""+ tunName +"\" address=8.8.8.8 index=1";
    //system(dnsCmd.c_str());


    checkAdapterStatus(wintunIndex);
}

HANDLE VirtualNetworkInterface::getReadWaitEvent(){
    return WintunGetReadWaitEvent(m_session);
}

int VirtualNetworkInterface::recv(BYTE* byteBuffer){
    DWORD packetSize;
    BYTE* wintunPacket = WintunReceivePacket(m_session, &packetSize);
    
    if (byteBuffer){
        if (packetSize >= 20){
            class_print("wintunRecv", "Packet recv'd with size: " + std::to_string(packetSize));
            packet_print(wintunPacket, packetSize);
            memcpy(byteBuffer, wintunPacket, packetSize);
            class_print("wintunRecv", "copied packet");
            return packetSize;
        }else{
            class_print("wintunRecv", "Packet length Below 20 bytes");
            WintunReleaseReceivePacket(m_session, byteBuffer);
        }
    }
    return 1;
}

int VirtualNetworkInterface::releasePacket(BYTE* packet){
    WintunReleaseReceivePacket(m_session, packet);
    return 1;
}


int VirtualNetworkInterface::send(BYTE* bytePacket, int packetSize){
    BYTE *packet = WintunAllocateSendPacket(m_session, packetSize);
    memcpy(packet, bytePacket, packetSize);
    WintunSendPacket(m_session, packet);
    return 1;
}

VirtualNetworkInterface::~VirtualNetworkInterface(){
    //Refinds the default gateway
    //system("ipconfig /renew");
}

void VirtualNetworkInterface::ping_test(){
    HANDLE WaitEvent = WintunGetReadWaitEvent(m_session);

    while(1){
        DWORD PacketSize;
        BYTE *Packet = WintunReceivePacket(m_session, &PacketSize);
        if (Packet){
            if (PacketSize >= 20){
                packet_print(Packet, PacketSize);
            }else{
                class_print("ping_test", "Packet length Below 20 bytes");
            }
            WintunReleaseReceivePacket(m_session, Packet);
        }
        else{
            DWORD LastError = GetLastError();

            switch (LastError){
                case ERROR_NO_MORE_ITEMS:
                    if (WaitForSingleObject(WaitEvent, INFINITE) == WAIT_OBJECT_0){
                        continue;
                    }
                    report_error("Wait for Single Object Failed");
                default:
                    printf("GetLastError #%d.\n", LastError);
                    report_error("Failed to read packet");
            }   
        }
    }
}

