#include "../header_files/VirtualNetworkInterface.h"


int max_print_spaces = 0;

void class_print(std::string classname, std::string str){
    std::string classname_tag = "[" + classname + "] ";
    int classname_tag_len = classname_tag.length();
    int max_spaces_diff = classname_tag_len - max_print_spaces;
    if (max_spaces_diff > max_print_spaces){
        max_print_spaces = classname_tag_len;
        
    } 
    else if (max_spaces_diff < 0){
        classname.append(max_spaces_diff, ' ');
    }
    std::cout << classname_tag << str << std::endl;
}

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
        std::cout << "[VirtualNetworkInterface] Loaded Wintun" << std::endl;
    }
    else {
        printf("GetLastError #%d.\n", GetLastError());
        report_error("Failed to load wintun");
    }

    //Addd actual GUID generator
    GUID SomeFixedGUID2 = { 0xdeadbeef, 0xface, 0x4ace, { 0x9e, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 } };

    WINTUN_ADAPTER_HANDLE Adapter2 = WintunCreateAdapter(L"HomeNet", L"Wintun", &SomeFixedGUID2);
    std::cout << "[VirtualNetworkInterface] Wintun Create Adapter Initialized" << std::endl;



}
