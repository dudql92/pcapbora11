#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif

//#include "pcap.h" // pcap 라이브러리 사용 선언
#include <pcap\pcap.h>
#include "test.h"
#define ETHER_ADDR_LEN 6

// MAC주소형태를 구조체로 선언 mac으로 타입지정
typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac;

// 이더넷 헤더(d_mac_addr,s_mac_addr,packet type까지가 이더넷헤더) 구조체
struct ether_header{
	u_char ether_dhost[ETHER_ADDR_LEN]; // d_mac_addr
	u_char ether_shost[ETHER_ADDR_LEN]; // s_mac_addr
	u_short ether_type; // 패킷 유형(이더넷 헤더 다음에 붙을 헤더의 심볼정보 저장)
}eth;

// 패킷 수집시에 pcap_loop에서 콜백으로 호출할 패킷핸들링 함수 프로토타입 선언
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

// 메인
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;

	// pcap_cimpile()에서 사용될 변수
	char packet_filter[]="tcp"; // 패킷 필터링에 사용될 문자열 포인터(ex; tcp, udp, src foo(발신지 foo), ip or udp)
	struct bpf_program fcode; // 특정 프로토콜 캡쳐하기 위한 정책정보 저장
	
	// alldevs에 리스트로 네트워크 디바이스 목록을 가져옴
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// alldevs에 가져온 네트워크 디바이스 목록 출력
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name); // 디바이스명
		if (d->description)
			printf(" (%s)\n", d->description); // 디바이스 설명(ex; Gigabit Ethernet NIC)
		else
			printf(" (No description available)\n");
	}

	// 디바이스 목록이 없다면
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	// 캡쳐할 NIC 선택
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);

	// NIC선택 예외 처리
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		
		pcap_freealldevs(alldevs);
		return -1;
	}

	// 선택한 NIC로 리스트에서 찾아가기
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	

	

	//  다비이스 open해서 패킷 수집방법 정의
	if ((adhandle= pcap_open_live(d->name,     // 선택한 디바이스 네임
		65536,               // 랜카드에 수신할 패킷 크기(길이)
		1,                    // promiscuous 모드로 설정 (nonzero means promiscuous)
		1000,               // 읽기 타임아웃 시간
		errbuf               // error buffer
		)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}


	if (pcap_compile(adhandle, // 디바이스 핸들
		&fcode, // 특정 프로토콜 선택한 필터링 정책 룰
		packet_filter, // 패킷 필터링 룰
		1, // 최적화 여부 
		0xffffff) <0 ) // IP주소에 사용되는 넷마스크 값
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	// pcap_compile의 내용을 적용(set)
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	// NIC로 패킷 수신중 출력
	printf("\nlistening on %s...\n", d->description);

	// 더 이상 다른 디바이스 리스트(랜카드 수집정보)는 필요 없으므로 free
	pcap_freealldevs(alldevs);

	// 패킷 캡쳐 시작
	pcap_loop(adhandle, // 선택한 디바이스 open한 핸들
		0,  // 무한루프로 계속 캡쳐할 것을 의미
		packet_handler, // 패킷이 캡쳐 되면 패킷 처리를 위한 콜백방식의 패킷 핸들러 정의
		NULL); // 패킷 데이터 포인터인데 보통 NULL

	pcap_close(adhandle); // 디바이스 핸들 close
	return 0;
}

// 이더넷 헤더 출력하기 위한 패킷 핸들러
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	// ether_header 구조체의 ether_type의 값은 아래 3개에서 이더넷 헤더 다음에 붙을 헤더의 심볼을 지정해준다.
#define IP_HEADER 0x0800

	//L3의 type 판단용 변수
	unsigned int ptype;

	// mac저장용 변수
	mac* destmac;
	mac* srcmac;

	destmac = (mac*)pkt_data; // 수신자 MAC주소
	srcmac = (mac*)(pkt_data + 6); // 송신자 MAC주소

	struct ether_header* eth; // 이더넷 헤더 구조체로 eth 변수 선언

	eth=(struct ether_header*)pkt_data;  // 캡쳐한 이더넷 헤더 정보 eth에 저장

	ptype=ntohs(eth->ether_type); // ether_type은 이더넷 헤더 다음에 올 헤더의 종류의 심볼을 가지고 있음
	// 네트워크 프로토콜은 기본적으로 big-endian이고 Intel은 little-endian이므로 컴퓨터 내부의 정보를 전송을 위해서는 little->big엔디언으로 변환을 위해 ntohs를 쓰고 라우터로부터 수신한 것은 htons를 통해 big->little엔디언으로 변환함


	// ether_type으로 이더넷 헤더 다음의 헤더 내용을 판별(상위 프로토콜)
	// 이더넷=2계층, IP,arp,rarp =3계층
	if(ntohs(eth->ether_type) == IP_HEADER)
	{
		//printf("Upper Protocol is IP HEADER(%04x)\n",ptype);
		//if((int)ptype == 0x0800){//Ether Header의  IP일때만
			ip_header *ih = (ip_header *)(eth+1);

			if(ih->protocol == 06){//IP Header의 Protocol==6이면 TCP
				udp_header *uh = (udp_header *) ((u_char*)ih + ((ih->ver_ihl & 0xf) * 4));

				//print Packet
				printf("***************** Packet Capture *******************\n");
				printf("\n");
				printf("Destination Mac Address : %02x:%02x:%02x:%02x:%02x:%02x \n",
					destmac->byte1,
					destmac->byte2,
					destmac->byte3,
					destmac->byte4,
					destmac->byte5,
					destmac->byte6 );           
				//printf("\n");
				printf("Source Mac Address      : %02x:%02x:%02x:%02x:%02x:%02x \n",
					srcmac->byte1,
					srcmac->byte2,
					srcmac->byte3,
					srcmac->byte4,
					srcmac->byte5,
					srcmac->byte6 );
				printf("\n");
				//print IP & Port
				printf("Src IP = %d.%d.%d.%d:%d -> Dst IP = %d.%d.%d.%d:%d\n",
					ih->saddr.byte1,
					ih->saddr.byte2,
					ih->saddr.byte3,
					ih->saddr.byte4,
					ntohs( uh->sport ),
					ih->daddr.byte1,
					ih->daddr.byte2,
					ih->daddr.byte3,
					ih->daddr.byte4,
					ntohs( uh->dport )
					);
			}


		//}
	}
	else
	{
		printf("Upper Protocol is NOT IP HEADER(%04x)\n",ptype);
	}

	printf("\n");
	printf("*******************************************************\n");
	printf("\n");
	printf("\n");
	printf("\n");

}