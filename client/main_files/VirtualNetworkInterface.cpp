#include "../header_files/VirtualNetworkInterface.h"

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

void packet_print(BYTE* Packet, DWORD PacketSize){
    IPVersion ver = static_cast<IPVersion>(Packet[0] >> 4);
    //IPProtocol protocol = static_cast<IPProtocol>(Packet[9]); // The 10th byte is the Protocol field in IPv4

    switch (ver){
        case IPVersion::IPv4:
            class_print("ping_test", 
                            "IP type: " 
                            + IPVersionToString(ver) 
                            + " | Protocol Type: " 
                            + IPProtocolToString(static_cast<IPProtocol>(Packet[9])) 
                            + " | Size: " 
                            + std::to_string(PacketSize));
            break;
        case IPVersion::IPv6:
            class_print("ping_test", "IP type: " 
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

/*
#define X(Name) ((*(FARPROC *)&Name = GetProcAddress(Wintun, #Name)) == NULL)
    if (X("WintunCreateAdapter") || X("WintunCloseAdapter") || X("WintunOpenAdapter") || X("WintunGetAdapterLUID") ||
        X("WintunGetRunningDriverVersion") || X("WintunDeleteDriver") || X("WintunSetLogger") || X("WintunStartSession") ||
        X("WintunEndSession") || X("WintunGetReadWaitEvent") || X("WintunReceivePacket") || X("WintunReleaseReceivePacket") ||
        X("WintunAllocateSendPacket") || X("WintunSendPacket"))
#undef X
    {
        DWORD LastError = GetLastError();
        FreeLibrary(Wintun);
        SetLastError(LastError);
        return NULL;
    }
*/
    return Wintun;
}

VirtualNetworkInterface::VirtualNetworkInterface(){
    HMODULE wintunLib = InitializeWintun();
    if ( wintunLib != NULL ){
        class_print("VirtualNetworkInterface", "Loaded Wintun");
    }
    else {
        printf("GetLastError #%d.\n", GetLastError());
        report_error("Failed to load wintun");
    }

    //Addd actual GUID generator
    GUID SomeFixedGUID2 = { 0xdeadbeef, 0xface, 0x4ace, { 0x9e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } };

    m_adapter = WintunCreateAdapter(L"HomeNet", L"Wintun", &SomeFixedGUID2);
    if (!m_adapter){
        printf("GetLastError #%d.\n", GetLastError());
        report_error("Failed to create adapter");
    }
    
    class_print("VirtualNetworkInterface", "Wintun Create Adapter Initialized");


}

void VirtualNetworkInterface::ping_test(){
    class_print("ping_test", "Starting ping test");
    MIB_UNICASTIPADDRESS_ROW AddressRow;
    class_print("ping_test", "Address Row");
    InitializeUnicastIpAddressEntry(&AddressRow);
    class_print("ping_test", "Ip address entry");
    WintunGetAdapterLUID(m_adapter, &AddressRow.InterfaceLuid);
    class_print("ping_test", "Combined adapter and address row");

    AddressRow.Address.Ipv4.sin_family = AF_INET;
    AddressRow.Address.Ipv4.sin_addr.S_un.S_addr = htonl((10 << 24) | (0 << 16) | (0 << 8) | (1 << 0)); /* 10.0.0.1*/
    AddressRow.OnLinkPrefixLength = 24; 
    AddressRow.DadState = IpDadStatePreferred;

    DWORD LastError = CreateUnicastIpAddressEntry(&AddressRow);
    if (LastError != ERROR_SUCCESS && LastError != ERROR_OBJECT_ALREADY_EXISTS){
        report_error("Failed to create Ip Address Entry, last error: " + LastError);
    }
    class_print("ping_test", "Created Ip Address Entry");

    WINTUN_SESSION_HANDLE Session = WintunStartSession(m_adapter, 0x400000);
    if (!Session)
    {
        printf("GetLastError #%d.\n", GetLastError());
        report_error("Failed to create wintun session");
    }
    class_print("ping_test", "Created session");
    char ipString[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &(AddressRow.Address.Ipv4.sin_addr), ipString, INET_ADDRSTRLEN)) {
        std::string txt = "Created Session with Address Row: ";
        class_print("ping_test", (txt.append(ipString)));
    } else {
        std::cerr << "Failed to convert IP address. Error: " << WSAGetLastError() << std::endl;
    }

    //in wintun example.c, two values are input read wait event and quit event, 
    // in the case of error no more items, it uses WaitForMultipleObjects which waits
    // for a new packet to be read or the signal to quit out of the while loop
    HANDLE WaitEvent = WintunGetReadWaitEvent(Session);

    while(1){
        DWORD PacketSize;
        BYTE *Packet = WintunReceivePacket(Session, &PacketSize);
        if (Packet){
            if (PacketSize >= 20){
                packet_print(Packet, PacketSize);
            }else{
                class_print("ping_test", "Packet length Below 20 bytes");
            }
            WintunReleaseReceivePacket(Session, Packet);
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

