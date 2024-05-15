#ifndef BPFOCKET_H
#define BPFOCKET_H


#include <iostream>
#include <sys/socket.h>
#include <net/ethernet.h>  // ETH_P_ALL
#include <netinet/in.h>    // htons()

#define __BPFOCKET_BEGIN namespace bpfocket {
#define __BPFOCKET_END   }

__BPFOCKET_BEGIN
namespace filter
{

}  // ::bpfocket::filter

namespace core
{
    class RawSocket
    {
    public:
        RawSocket();
    private:
        void create();
    };

    RawSocket::RawSocket()
    {
        create();
    }

    void RawSocket::create()
    {
        //socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    }
}  // ::bpfocket::core
__BPFOCKET_END


#endif  // BPFOCKET_H

//#include <linux/filter.h>  // struct sock_filter
//
//#include <sys/socket.h>
//#include <sys/ioctl.h>     // ioctl()
//#include <sys/file.h>
//
//#include <unistd.h>        // close()
//#include <net/if.h>        // struct ifconf, struct ifreq
//#include <net/if_arp.h>    // ARPHDR_ETHER
//#include <net/ethernet.h>
//#include <netinet/ip.h>
//#include <netinet/tcp.h>
//#include <netinet/udp.h>
//#include <netinet/in.h>    // htons()
//#include <arpa/inet.h>     // inet_ntoa()
//
//#include <cstring>         // strncpy()
//#include <string>
//#include <queue>
//#include <iostream>
//#include <vector>
//
//
//void print_errno();
//void print_packet(const u_char*, size_t);
//
//enum class eProtocolID
//{
//    Ip = ETH_P_IP,
//    Tcp = IPPROTO_TCP,
//    Udp = IPPROTO_UDP,
//};
//
//std::vector<struct sock_filter> gen_bpf_code(eProtocolID protocol_id)
//{
//    std::vector<struct sock_filter> bpf_code{};
//
//    bpf_code.push_back(
//        BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
//                 offsetof(struct ether_header, ether_type)));
//
//    if (protocol_id == eProtocolID::Ip)
//    {
//        bpf_code.push_back(
//            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 1));
//    }
//    else  // Tcp or Udp
//    {
//        bpf_code.push_back(
//            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 3));
//        bpf_code.push_back(
//            BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
//                     ETH_HLEN + offsetof(struct iphdr, protocol)));
//        bpf_code.push_back(
//            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
//                     static_cast<uint16_t>(protocol_id), 0, 1));
//    }
//
//    bpf_code.push_back(BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF));
//    bpf_code.push_back(BPF_STMT(BPF_RET + BPF_K, 0x00));
//
//    return bpf_code;
//}
//
///*
//static struct sock_filter IPv4_BPF_CODE[] = {
//    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_header, ether_type)),
//    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 1),
//        BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),  // return
//
//    BPF_STMT(BPF_RET + BPF_K, 0x00),  // return
//};
//
//static struct sock_filter TCP_BPF_CODE[] = {
//    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ether_header, ether_type)),
//    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 3),
//        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETH_HLEN + offsetof(struct iphdr, protocol)),
//        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 0, 1),
//            BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),  // return
//
//    BPF_STMT(BPF_RET + BPF_K, 0x00),  // return
//};
//
//static struct sock_filter UDP_BPF_CODE[] = {
//    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, offsetof(struct ethhdr, h_proto)),
//    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 3),
//        BPF_STMT(BPF_LD + BPF_B + BPF_ABS, ETH_HLEN + offsetof(struct iphdr, protocol)),
//        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_UDP, 0, 1),
//            BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),  // return
//
//    BPF_STMT(BPF_RET + BPF_K, 0x00),  // return
//};
//*/
//
//int main()
//{
//    // Create socket
//    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
//    if (sockfd < 0)
//    {
//        std::cerr << "socket(...) failed..." << std::endl;
//        print_errno();
//        return 1;
//    }
//
//    /// Get interface config
//    //  1. get if config length
//    struct ifconf ifc{};
//    ifc.ifc_len = 0;
//    ifc.ifc_buf = nullptr;
//    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0)
//    {
//        std::cerr << "ioctl(..., SIOCGIFCONF, ...) failed..." << std::endl;
//        print_errno();
//        return 2;
//    }
//
//    //  2. get interfaces
//    std::vector<char> buf{};
//    buf.reserve(ifc.ifc_len);
//    ifc.ifc_buf = buf.data();
//    if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0)
//    {
//        std::cerr << "ioctl(..., SIOCGIFCONF, ...) failed..." << std::endl;
//        print_errno();
//        return 3;
//    }
//
//    // Get ethernet interface using hardware address
//    std::string ifname{};
//    std::string dev{};
//    struct ifreq eth_ifr{};
//    struct ifreq* ifr{ ifc.ifc_req };
//    for (size_t i = 0; i < ifc.ifc_len / sizeof(struct ifreq); i++)
//    {
//        if (ioctl(sockfd, SIOCGIFFLAGS, &ifr[i]) < 0)
//        {
//            std::cerr << "ioctl(..., SIOCGIFFLAGS, ...)" << std::endl;
//            print_errno();
//            return 5;
//        }
//
//        if ((ifr[i].ifr_flags & IFF_LOOPBACK) ||
//            !(ifr[i].ifr_flags & IFF_UP) ||
//            !(ifr[i].ifr_flags & IFF_RUNNING))
//        {
//            continue;
//        }
//
//        if (ioctl(sockfd, SIOCGIFHWADDR, &ifr[i]) < 0)
//        {
//            std::cerr <<
//                "ioctl(..., SIOCGIFHWADDR, ...) failed..." << std::endl;
//            print_errno();
//            return 4;
//        }
//
//        if (ifr[i].ifr_hwaddr.sa_family != ARPHRD_ETHER)
//        {
//            continue;
//        }
//
//        std::cout <<
//            "Ethernet Interface found: " << ifr[i].ifr_name << std::endl;
//
//        std::vector<std::string> ifname_vec{};
//        if (ifname.empty())
//        {
//            ifname_vec.push_back("eth");
//            ifname_vec.push_back("en");
//        }
//        else
//        {
//            ifname_vec.push_back(ifname);
//        }
//
//        const std::string eth_ifr_name = ifr[i].ifr_name;
//        for (const auto& e : ifname_vec)
//        {
//            if (eth_ifr_name.find(e) != std::string::npos)
//            {
//                eth_ifr = ifr[i];
//                dev = eth_ifr_name;
//                break;
//            }
//        }
//    }
//
//    if (dev.empty())
//    {
//        std::cerr << "No suitable ethernet interface found." << std::endl;
//        return -1;
//    }
//
//    std::cout << "dev: " << dev << std::endl;
//
//    //strncpy(eth_ifr.ifr_name, dev.c_str(), dev.length() + 1);
//
//    // Get flags
//    if (ioctl(sockfd, SIOCGIFFLAGS, &eth_ifr) < 0)
//    {
//        std::cerr << "ioctl(..., SIOCGIFFLAGS, ...)" << std::endl;
//        print_errno();
//        return 5;
//    }
//
//    struct ifreq orig_eth_ifr{ eth_ifr };
//    std::cout << "orig_eth_ifr.ifr_name: " << orig_eth_ifr.ifr_name << '\n'
//              << "orig_eth_ifr.ifr_flags: " << std::hex << orig_eth_ifr.ifr_flags
//    << std::endl;
//
//    std::cout << "IFF_PROMISC: " << std::hex << IFF_PROMISC << std::endl;
//    std::cout << "eth_ifr.ifr_flags |= IFF_PROMISC" << std::endl;
//
//    // Set promisc flag
//    eth_ifr.ifr_flags |= IFF_PROMISC;
//    if (ioctl(sockfd, SIOCSIFFLAGS, &eth_ifr) < 0)
//    {
//        std::cerr << "ioctl(..., SIOCSIFFLAGS, ...)" << std::endl;
//        print_errno();
//        return 6;
//    }
//
//    std::cout << "eth_ifr.ifr_name: " << eth_ifr.ifr_name << '\n'
//              << "eth_ifr.ifr_flags: " << std::hex << eth_ifr.ifr_flags
//    << std::endl;
//
//    // Set socket options
//    if (setsockopt(sockfd,
//                   SOL_SOCKET,
//                   SO_BINDTODEVICE,
//                   dev.c_str(),
//                   dev.length()) < 0)
//    {
//        std::cerr <<
//            "setsockopt(..., SO_BINDTODEVICE, ...) failed..." << std::endl;
//        print_errno();
//        return 7;
//    }
//
//    // Set filter
//    //std::vector<struct sock_filter> bpf_code{ gen_bpf_code(eProtocolID::Tcp) };
//    std::vector<struct sock_filter> bpf_code{ gen_bpf_code(eProtocolID::Udp) };
//    struct sock_fprog filter{};
//    filter.len = bpf_code.size();
//    filter.filter = bpf_code.data();
//
//    //filter.len = sizeof(TCP_BPF_CODE) / sizeof(TCP_BPF_CODE[0]);
//    //filter.len = sizeof(udp_bpf_code) / sizeof(udp_bpf_code[0]);
//    //filter.filter = TCP_BPF_CODE;
//    //filter.filter = udp_bpf_code;
//    if (setsockopt(sockfd,
//                   SOL_SOCKET,
//                   SO_ATTACH_FILTER,
//                   &filter,
//                   sizeof(filter)) < 0)
//    {
//        std::cerr <<
//            "setsockopt(..., SO_ATTACH_FILTER, ...) failed..." << std::endl;
//        print_errno();
//        return 8;
//    }
//
//    static constexpr size_t BUF_SIZE = 4096;
//    int recv_bytes = 0;
//    int n = 0;
//    u_char data_buf[BUF_SIZE] = { 0, };
//    /*
//    while (1)
//    {
//        recv_bytes = 0;
//        while(1)
//        {
//            n = recvfrom(sockfd, data_buf, BUF_SIZE, 0, NULL, NULL);
//            if (n < 0)
//            {
//                std::cerr << "recvfrom(...) failed..." << std::endl;
//                print_errno();
//                return -1;
//            }
//
//            if (n == 0)
//            {
//                break;
//            }
//
//            recv_bytes += n;
//            if (n < BUF_SIZE)
//            {
//                break;
//            }
//        }
//
//        if (recv_bytes < 42)
//        {
//            printf("%d\n", recv_bytes);
//            perror("recvfrom(...): ");
//            printf("Incomplete packet (errno is %d)\n", errno);
//            close(sockfd);
//            return 7;
//        }
//
//        struct ether_header* eth_hdr = (struct ether_header*)data_buf;
//
//        printf("Src: %02x", eth_hdr->ether_shost[0]);
//        for (size_t i = 1; i < 6; i++)
//        {
//            printf(":%02x", eth_hdr->ether_shost[i]);
//        }
//        printf("\n");
//
//        printf("Dst: %02x", eth_hdr->ether_dhost[0]);
//        for (size_t i = 1; i < 6; i++)
//        {
//            printf(":%02x", eth_hdr->ether_dhost[i]);
//        }
//        printf("\n");
//
//        struct iphdr* ip_hdr =
//            (struct iphdr*)(data_buf + sizeof(struct ether_header));
//
//        struct in_addr ip_addr{};
//        ip_addr.s_addr = ip_hdr->saddr;
//        printf("Src: %s\n", inet_ntoa(ip_addr));
//        ip_addr.s_addr = ip_hdr->daddr;
//        printf("Dst: %s\n", inet_ntoa(ip_addr));
//
//        const u_char* payload =
//            data_buf + sizeof(struct ether_header) + (ip_hdr->ihl * 4);
//        struct tcphdr* tcp_hdr{};
//        struct udphdr* udp_hdr{};
//        switch (ip_hdr->protocol)
//        {
//        case IPPROTO_TCP:
//            tcp_hdr = (struct tcphdr*)payload;
//            std::cout << ntohs(tcp_hdr->source) << std::endl;
//            std::cout << ntohs(tcp_hdr->dest) << std::endl;
//            break;
//        case IPPROTO_UDP:
//            udp_hdr = (struct udphdr*)payload;
//            std::cout << "Total Len: " << ntohs(udp_hdr->len) << '\n';
//            std::cout << "Src Port: " << ntohs(udp_hdr->source) << '\n';
//            std::cout << "Dst Port: " << ntohs(udp_hdr->dest) << '\n';
//            break;
//        default:
//            break;
//        }
//
//        std::cout << std::endl;
//
//        print_packet(data_buf, recv_bytes);
//        std::cout << std::endl;
//    }
//    */
//
//    // Set non-promisc mode
//    if (ioctl(sockfd, SIOCSIFFLAGS, &orig_eth_ifr) < 0)
//    {
//        std::cerr << "ioctl(..., SIOCSIFFLAGS, ...)" << std::endl;
//        print_errno();
//        return -1;
//    }
//
//    close(sockfd);
//
//    return 0;
//}
//
//void print_errno()
//{
//    std::cerr << "errno: " << errno << std::endl;
//    perror("error: ");
//}
//
//void print_packet(const u_char* packet, size_t packet_len)
//{
//    printf("\\---------------------------------------------------------------/\n");
//
//    int cnt = 0;
//    std::queue<u_char> q{};
//    while (packet_len--)
//    {
//        u_char ch = *(packet++);
//        printf("%02x ", ch);
//        q.push(ch);
//        if ((++cnt % 16) == 0)
//        {
//            while (!q.empty())
//            {
//                u_int n{ q.front() };
//                if (n > 32 && n < 126 )
//                {
//                    printf("%c", n);
//                }
//                else
//                {
//                    printf(".");
//                }
//                q.pop();
//            }
//            printf("\n");
//        }
//    }
//
//    if (!q.empty())
//    {
//        for (size_t i = 0; i < 16 - q.size(); i++)
//        {
//            printf("   ");
//        }
//
//        while (!q.empty())
//        {
//            u_int n{ q.front() };
//            if (n > 32 && n < 126 )
//            {
//                printf("%c", n);
//            }
//            else
//            {
//                printf(".");
//            }
//            q.pop();
//        }
//    }
//}