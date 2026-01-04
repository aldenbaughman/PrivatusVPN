#pragma once
#include <string>

enum class IPVersion : unsigned char {
    IPv4 = 4,
    IPv6 = 6
};

enum class IPProtocol : unsigned char {
    HOPOPT   = 0,
    ICMP     = 1,
    IGMP     = 2,
    TCP      = 6,
    UDP      = 17,
    IPv6ICMP = 58,
    SCTP     = 132,
    RAW      = 255
};

inline std::string IPVersionToString(IPVersion version) {
    switch (version) {
        case IPVersion::IPv4: return "IPv4";
        case IPVersion::IPv6: return "IPv6";
        default: return "Unknown (" + std::to_string((int)version) + ")";
    }
}

inline std::string IPProtocolToString(IPProtocol proto) {
    switch (proto) {
        case IPProtocol::HOPOPT:     return "HOPOPT";
        case IPProtocol::ICMP:     return "ICMP";
        case IPProtocol::IGMP:     return "IGMP";
        case IPProtocol::TCP:      return "TCP ";
        case IPProtocol::UDP:      return "UDP ";
        case IPProtocol::IPv6ICMP: return "IPv6-ICMP";
        case IPProtocol::SCTP:     return "SCTP";
        case IPProtocol::RAW:      return "RAW ";
        default: return "Unknown (" + std::to_string((int)proto) + ")";
    }
}
