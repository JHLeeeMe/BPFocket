/// bpfapture_test.cpp
///

// ReSharper disable CppDFAUnusedValue

#include <fcntl.h>  // fcntl()

#include <iostream>

#include "gtest/gtest.h"

//#include "bpfocket.h"
#include "bpfocket/bpfapture.h"

TEST(ioctl, getconf)
{  // ::ioctl()
    using namespace bpfapture;

    core::BPFapture sock{ false };
    const int sockfd = sock.fd();

    struct ifconf ifc{};
    ifc.ifc_len = 0;
    ifc.ifc_buf = nullptr;

    int retval = 0;
    int len = 0;
    {  // set ifc.ifc_len
        retval = ::ioctl(sockfd, SIOCGIFCONF, &ifc);
        ASSERT_EQ(0, retval);
        ASSERT_EQ(nullptr, ifc.ifc_buf);

        ASSERT_NE(0, ifc.ifc_len);
        len = ifc.ifc_len;
    }

    std::vector<char> buf{};
    {  // set all using ifc.ifc_len
        buf.reserve(ifc.ifc_len);
        buf.resize(ifc.ifc_len);
        ifc.ifc_buf = buf.data();

        retval = ::ioctl(sockfd, SIOCGIFCONF, &ifc);
        ASSERT_EQ(len, ifc.ifc_len);

        ASSERT_NE(nullptr, ifc.ifc_buf);
    }
}

TEST(throwRuntimeError, all)
{  // ::bpfocket::bpfapture::utils
    using namespace bpfapture;

    constexpr ssize_t err_no = 1;

    ASSERT_THROW(
        utils::throwRuntimeError(
            utils::eResultCode::Failure, err_no, __FUNCTION__),
        std::runtime_error
    );
}

TEST(gen_bpf_code, all)
{  // ::bpfocket::bpfapture::filter
    using namespace bpfapture;

    auto lambda_gen_bpf_code_test =
        [](const struct sock_filter* expected_arr,
           const std::vector<filter::eProtocolID>& proto_ids) -> void
        {
            const std::vector<struct sock_filter> generated_vec{
                filter::gen_bpf_code(proto_ids) };

            for (size_t i = 0; i < generated_vec.size(); i++)
            {
                ASSERT_EQ(expected_arr[i].code, generated_vec[i].code);
                ASSERT_EQ(expected_arr[i].jt, generated_vec[i].jt);
                ASSERT_EQ(expected_arr[i].jf, generated_vec[i].jf);
                ASSERT_EQ(expected_arr[i].k, generated_vec[i].k);
            }
        };

    {  // ip
        std::vector<filter::eProtocolID> ip_ids_1{ filter::eProtocolID::Ip };
        std::set<filter::eProtocolID> set_ip_ids_1{ ip_ids_1.begin(),
                                                    ip_ids_1.end() };
        struct sock_filter ip_bpf_code_1[] = {
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                     offsetof(struct ether_header, ether_type)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        };

        std::vector<filter::eProtocolID> ip_ids_3{ filter::eProtocolID::Ip,
                                                   filter::eProtocolID::Ip,
                                                   filter::eProtocolID::Ip };
        std::set<filter::eProtocolID> set_ip_ids_3{ ip_ids_3.begin(),
                                                    ip_ids_3.end() };
        struct sock_filter ip_bpf_code_3[] = {
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                     offsetof(struct ether_header, ether_type)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        };

        lambda_gen_bpf_code_test(ip_bpf_code_1, ip_ids_1);
        lambda_gen_bpf_code_test(ip_bpf_code_3, ip_ids_3);
    }

    {  // tcp
        std::vector<filter::eProtocolID> tcp_ids_1{ filter::eProtocolID::Tcp };
        std::set<filter::eProtocolID> set_tcp_ids_1{ tcp_ids_1.begin(),
                                                     tcp_ids_1.end() };
        struct sock_filter tcp_bpf_code_1[] = {
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                     offsetof(struct ether_header, ether_type)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
                     ETHER_HDR_LEN + offsetof(struct iphdr, protocol)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                     static_cast<uint16_t>(filter::eProtocolID::Tcp), 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        };

        std::vector<filter::eProtocolID> tcp_ids_2{ filter::eProtocolID::Tcp,
                                                    filter::eProtocolID::Ip, };
        std::set<filter::eProtocolID> set_tcp_ids_2{ tcp_ids_2.begin(),
                                                     tcp_ids_2.end() };
        struct sock_filter tcp_bpf_code_2[] = {
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                     offsetof(struct ether_header, ether_type)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
                     ETHER_HDR_LEN + offsetof(struct iphdr, protocol)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                     static_cast<uint16_t>(filter::eProtocolID::Tcp), 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        };

        std::vector<filter::eProtocolID> tcp_ids_5{ filter::eProtocolID::Ip,
                                                    filter::eProtocolID::Tcp,
                                                    filter::eProtocolID::Tcp,
                                                    filter::eProtocolID::Ip,
                                                    filter::eProtocolID::Tcp, };
        std::set<filter::eProtocolID> set_tcp_ids_5{ tcp_ids_5.begin(),
                                                     tcp_ids_5.end() };
        struct sock_filter tcp_bpf_code_5[] = {
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                     offsetof(struct ether_header, ether_type)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
                     ETHER_HDR_LEN + offsetof(struct iphdr, protocol)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                     static_cast<uint16_t>(filter::eProtocolID::Tcp), 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        };

        lambda_gen_bpf_code_test(tcp_bpf_code_1, tcp_ids_1);
        lambda_gen_bpf_code_test(tcp_bpf_code_2, tcp_ids_2);
        lambda_gen_bpf_code_test(tcp_bpf_code_5, tcp_ids_5);
    }

    { // tcp & udp & icmp
        std::vector<filter::eProtocolID> ids_5{ filter::eProtocolID::Ip,
                                                filter::eProtocolID::Udp,
                                                filter::eProtocolID::Icmp,
                                                filter::eProtocolID::Ip,
                                                filter::eProtocolID::Tcp, };
        std::set<filter::eProtocolID> set_ids_5{ ids_5.begin(),
                                                 ids_5.end() };
        struct sock_filter bpf_code_5[] = {
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                     offsetof(struct ether_header, ether_type)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
                     ETHER_HDR_LEN + offsetof(struct iphdr, protocol)),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                     static_cast<uint16_t>(filter::eProtocolID::Icmp), 3, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                     static_cast<uint16_t>(filter::eProtocolID::Tcp), 2, 0),
            BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                     static_cast<uint16_t>(filter::eProtocolID::Udp), 1, 0),
            BPF_STMT(BPF_RET + BPF_K, 0x00),
            BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        };

        lambda_gen_bpf_code_test(bpf_code_5, ids_5);
    }
}

TEST(BPFapture, rule_of_X)
{  // ::bpfocket::bpfapture::core
    using namespace bpfapture;
    namespace bpfapture = ::bpfocket::bpfapture;

    auto lambda_constructor_destructor_test = [](bool promisc) -> void {
        core::BPFapture sock{ promisc };
        ASSERT_EQ(typeid(sock), typeid(core::BPFapture));

        {
            struct ifreq ifr{};
            const std::string ifname = sock.ifname();
            strncpy(ifr.ifr_name, ifname.c_str(), ifname.length() + 1);

            ::ioctl(sock.fd(), SIOCGIFFLAGS, &ifr);

            const uint16_t flags = ifr.ifr_flags;
            ASSERT_EQ(0, flags & IFF_LOOPBACK);
            ASSERT_EQ(IFF_UP, flags & IFF_UP);
            ASSERT_EQ(IFF_RUNNING, flags & IFF_RUNNING);
        }

        errno = 0;
        int fd_tmp{};
        { // destructor
            core::BPFapture sock_tmp{ promisc };
            fd_tmp = sock_tmp.fd();
            ASSERT_NE(0, fd_tmp);
            ASSERT_NE(-1, fcntl(fd_tmp, F_GETFD));
            ASSERT_NE(EBADF, errno);
        }
        ASSERT_EQ(-1, fcntl(fd_tmp, F_GETFD));
        ASSERT_EQ(EBADF, errno);

        {  // err()
            ASSERT_EQ(0, sock.err());
        }
    };

    lambda_constructor_destructor_test(false);  // promisc = flase
    lambda_constructor_destructor_test(true);   // promisc = true

    {  // Move
        {  // constructor
            core::BPFapture sock{};
            ASSERT_NE(-1, fcntl(sock.fd(), F_GETFD));

            int sockfd = sock.fd();
            std::string ifname{ sock.ifname() };

            // move constructor
            core::BPFapture sock_move{ std::move(sock) };
            ASSERT_NE(-1, fcntl(sock_move.fd(), F_GETFD));

            // compare new & orig
            ASSERT_EQ(-1, sock.fd());
            ASSERT_EQ(sockfd, sock_move.fd());
            ASSERT_EQ(ifname, sock_move.ifname());
            ASSERT_EQ(-1, fcntl(sock.fd(), F_GETFD));
            ASSERT_EQ(EBADF, errno);
        }

        {  // operator=
            core::BPFapture sock{};
            ASSERT_NE(-1, fcntl(sock.fd(), F_GETFD));

            int sockfd = sock.fd();
            std::string ifname{ sock.ifname() };

            // move assignment operator
            core::BPFapture sock_move_op{};
            sock_move_op = std::move(sock);
            ASSERT_NE(-1, fcntl(sock_move_op.fd(), F_GETFD));

            // compare new & orig
            ASSERT_EQ(-1, sock.fd());
            ASSERT_EQ(sockfd, sock_move_op.fd());
            ASSERT_EQ(ifname, sock_move_op.ifname());
            ASSERT_EQ(-1, fcntl(sock.fd(), F_GETFD));
            ASSERT_EQ(EBADF, errno);
        }
    }

    {  // Copy (Compile error)
        //core::BPFapture sock{};

        /// copy constructor
        // core::BPFapture sock_copy{ sock };

        /// copy assignment operator
        // core::BPFapture sock_copy_op{};
        // sock_copy_op = sock;
    }
}

TEST(BPFapture, set_ifname)
{  // ::bpfocket::bpfapture::core
    /// set_ifname() is exec in constructor
    ///

    using namespace bpfapture;

    core::BPFapture sock{ false };
    ASSERT_NE(std::string(), sock.ifname());
}

TEST(BPFapture, set_filter)
{  // ::bpfocket::bpfapture::core
    using namespace bpfapture;

    std::vector<filter::eProtocolID> proto_ids{ filter::eProtocolID::Tcp,
                                                filter::eProtocolID::Udp };
    core::BPFapture sock{};
    sock.set_filter(proto_ids);
    if (sock.err() != 0)
    {
        std::cerr << sock.err() << std::endl;
        return;
    }

    std::vector<struct sock_filter> filter_vec{
        filter::gen_bpf_code(proto_ids) };

    const struct sock_fprog filter{ sock.filter() };
    ASSERT_EQ(filter.len, filter_vec.size());
}

TEST(BPFapture, set_mtu)
{  // ::bpfocket::bpfapture::core
    /// set_mtu() is exec in constructor
    ///

    using namespace bpfapture;

    core::BPFapture sock{};
    const int sockfd = sock.fd();

    struct ifreq ifr{};
    strncpy(ifr.ifr_name, sock.ifname().c_str(), sock.ifname().length());
    if (::ioctl(sockfd, SIOCGIFMTU, &ifr) < 0)
    {
        perror("ioctl");
        return;
    }

    ASSERT_EQ(ifr.ifr_mtu, sock.mtu());
}

TEST(BPFapture, receive)
{  // ::bpfocket::bpfapture::core
    using namespace bpfapture;

    core::BPFapture sock{ true };
    int system_mtu = sock.mtu();

    std::vector<filter::eProtocolID> proto_ids{ filter::eProtocolID::Icmp,
                                                filter::eProtocolID::Tcp, };
    utils::eResultCode code{ sock.set_filter(proto_ids) };
    if (code != utils::eResultCode::Success)
    {
        std::ostringstream oss{};
        oss << "[code: " << static_cast<uint32_t>(code) << "]";
        if (sock.err() != 0)
        {
            oss << "[errno: " << sock.err() << "]";
        }

        std::cerr << oss.str() << std::endl;
        return;
    }

    ASSERT_EQ(system_mtu, sock.mtu());
    std::vector<uint8_t> buf(sock.mtu());
    ssize_t received_bytes = 0;

    int max_cnt = 10;
    while (max_cnt--)
    {
        if ((received_bytes = sock.receive(buf.data(), buf.size())) < 0)
        {
            std::cerr << sock.err() << std::endl;
            return;
        }

        for (size_t i = 0; i < received_bytes; i++)
        {
            if (i != 0 && i % 16 == 0)
            {
                std::cout << std::endl;
            }

            uint8_t c = buf[i];
            if (c > 32 && c < 126 )
            {
                printf("%c", c);
            }
            else
            {
                printf(".");
            }
        }
        std::cout << std::endl;
    }
    std::cout << std::endl;
}
