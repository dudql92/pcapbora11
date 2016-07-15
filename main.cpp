#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif

//#include "pcap.h" // pcap ���̺귯�� ��� ����
#include <pcap\pcap.h>
#include "test.h"
#define ETHER_ADDR_LEN 6

// MAC�ּ����¸� ����ü�� ���� mac���� Ÿ������
typedef struct mac_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
	u_char byte5;
	u_char byte6;
}mac;

// �̴��� ���(d_mac_addr,s_mac_addr,packet type������ �̴������) ����ü
struct ether_header{
	u_char ether_dhost[ETHER_ADDR_LEN]; // d_mac_addr
	u_char ether_shost[ETHER_ADDR_LEN]; // s_mac_addr
	u_short ether_type; // ��Ŷ ����(�̴��� ��� ������ ���� ����� �ɺ����� ����)
}eth;

// ��Ŷ �����ÿ� pcap_loop���� �ݹ����� ȣ���� ��Ŷ�ڵ鸵 �Լ� ������Ÿ�� ����
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

// ����
int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;

	// pcap_cimpile()���� ���� ����
	char packet_filter[]="tcp"; // ��Ŷ ���͸��� ���� ���ڿ� ������(ex; tcp, udp, src foo(�߽��� foo), ip or udp)
	struct bpf_program fcode; // Ư�� �������� ĸ���ϱ� ���� ��å���� ����
	
	// alldevs�� ����Ʈ�� ��Ʈ��ũ ����̽� ����� ������
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}

	// alldevs�� ������ ��Ʈ��ũ ����̽� ��� ���
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name); // ����̽���
		if (d->description)
			printf(" (%s)\n", d->description); // ����̽� ����(ex; Gigabit Ethernet NIC)
		else
			printf(" (No description available)\n");
	}

	// ����̽� ����� ���ٸ�
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	// ĸ���� NIC ����
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);

	// NIC���� ���� ó��
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		
		pcap_freealldevs(alldevs);
		return -1;
	}

	// ������ NIC�� ����Ʈ���� ã�ư���
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	

	

	//  �ٺ��̽� open�ؼ� ��Ŷ ������� ����
	if ((adhandle= pcap_open_live(d->name,     // ������ ����̽� ����
		65536,               // ��ī�忡 ������ ��Ŷ ũ��(����)
		1,                    // promiscuous ���� ���� (nonzero means promiscuous)
		1000,               // �б� Ÿ�Ӿƿ� �ð�
		errbuf               // error buffer
		)) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}


	if (pcap_compile(adhandle, // ����̽� �ڵ�
		&fcode, // Ư�� �������� ������ ���͸� ��å ��
		packet_filter, // ��Ŷ ���͸� ��
		1, // ����ȭ ���� 
		0xffffff) <0 ) // IP�ּҿ� ���Ǵ� �ݸ���ũ ��
	{
		fprintf(stderr,"\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	// pcap_compile�� ������ ����(set)
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		fprintf(stderr,"\nError setting the filter.\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	// NIC�� ��Ŷ ������ ���
	printf("\nlistening on %s...\n", d->description);

	// �� �̻� �ٸ� ����̽� ����Ʈ(��ī�� ��������)�� �ʿ� �����Ƿ� free
	pcap_freealldevs(alldevs);

	// ��Ŷ ĸ�� ����
	pcap_loop(adhandle, // ������ ����̽� open�� �ڵ�
		0,  // ���ѷ����� ��� ĸ���� ���� �ǹ�
		packet_handler, // ��Ŷ�� ĸ�� �Ǹ� ��Ŷ ó���� ���� �ݹ����� ��Ŷ �ڵ鷯 ����
		NULL); // ��Ŷ ������ �������ε� ���� NULL

	pcap_close(adhandle); // ����̽� �ڵ� close
	return 0;
}

// �̴��� ��� ����ϱ� ���� ��Ŷ �ڵ鷯
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	// ether_header ����ü�� ether_type�� ���� �Ʒ� 3������ �̴��� ��� ������ ���� ����� �ɺ��� �������ش�.
#define IP_HEADER 0x0800

	//L3�� type �Ǵܿ� ����
	unsigned int ptype;

	// mac����� ����
	mac* destmac;
	mac* srcmac;

	destmac = (mac*)pkt_data; // ������ MAC�ּ�
	srcmac = (mac*)(pkt_data + 6); // �۽��� MAC�ּ�

	struct ether_header* eth; // �̴��� ��� ����ü�� eth ���� ����

	eth=(struct ether_header*)pkt_data;  // ĸ���� �̴��� ��� ���� eth�� ����

	ptype=ntohs(eth->ether_type); // ether_type�� �̴��� ��� ������ �� ����� ������ �ɺ��� ������ ����
	// ��Ʈ��ũ ���������� �⺻������ big-endian�̰� Intel�� little-endian�̹Ƿ� ��ǻ�� ������ ������ ������ ���ؼ��� little->big��������� ��ȯ�� ���� ntohs�� ���� ����ͷκ��� ������ ���� htons�� ���� big->little��������� ��ȯ��


	// ether_type���� �̴��� ��� ������ ��� ������ �Ǻ�(���� ��������)
	// �̴���=2����, IP,arp,rarp =3����
	if(ntohs(eth->ether_type) == IP_HEADER)
	{
		//printf("Upper Protocol is IP HEADER(%04x)\n",ptype);
		//if((int)ptype == 0x0800){//Ether Header��  IP�϶���
			ip_header *ih = (ip_header *)(eth+1);

			if(ih->protocol == 06){//IP Header�� Protocol==6�̸� TCP
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