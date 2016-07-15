#include <Windows.h>

////6 bytes mac 주소
//typedef struct mac_address{
//	u_char byte1;
//    u_char byte2;
//    u_char byte3;
//    u_char byte4;
//	u_char byte5;
//    u_char byte6;
//}mac_address;
//
////이더넷 헤더
//struct ether_header{
//     u_char ether_dhost[ETHER_ADDR_LEN]; // d_mac_addr
//     u_char ether_shost[ETHER_ADDR_LEN]; // s_mac_addr
//     u_short ether_type; // 패킷 유형(이더넷 헤더 다음에 붙을 헤더의 심볼정보 저장)
//}eth;


/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;


/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service 
    u_short tlen;           // Total length 
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  protocol;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* TCP header*/
typedef struct udp_header{
    u_short sport;          // Source port
    u_short dport;          // Destination port
    u_short len;            // Datagram length
    u_short crc;            // Checksum
}udp_header;