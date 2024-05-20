/// bpfocket_test.cpp
///

#include <fcntl.h>  // fcntl()

#include <iostream>

#include "gtest/gtest.h"

//#include "bpfocket.h"
#include "bpfocket/bpfapture.h"

TEST(ioctl, getconf)
{  // ::ioctl()
    using namespace bpfapture;

    core::BPFapture sock{ false };
    int sockfd = sock.fd();

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

    ssize_t err_no = 1;

    ASSERT_THROW(
        utils::throwRuntimeError(
            utils::eResultCode::Failure, err_no, __FUNCTION__),
        std::runtime_error
    );
}

TEST(gen_bpf_code, all)
{  // ::bpfocket::bpfapture::filter
    using namespace bpfapture;

    struct sock_filter ip_bpf_code[] = {
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                 offsetof(struct ether_header, ether_type)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 1),
        BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        BPF_STMT(BPF_RET + BPF_K, 0x00),
    };

    struct sock_filter tcp_bpf_code[] = {
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                 offsetof(struct ether_header, ether_type)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 3),
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
                 ETH_HLEN + offsetof(struct iphdr, protocol)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                 static_cast<uint16_t>(filter::eProtocolID::Tcp), 0, 1),
        BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        BPF_STMT(BPF_RET + BPF_K, 0x00),
    };

    struct sock_filter udp_bpf_code[] = {
        BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                 offsetof(struct ether_header, ether_type)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 3),
        BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
                 ETH_HLEN + offsetof(struct iphdr, protocol)),
        BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                 static_cast<uint16_t>(filter::eProtocolID::Udp), 0, 1),
        BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF),
        BPF_STMT(BPF_RET + BPF_K, 0x00),
    };

    auto lambda_gen_bpf_code_test =
        [](struct sock_filter* code, filter::eProtocolID proto_id) {
            std::vector<struct sock_filter> bpf_code{
                filter::gen_bpf_code(proto_id) };

            int idx = 0;
            for (const auto& e : bpf_code)
            {
                ASSERT_EQ(code[idx].code, e.code);
                ASSERT_EQ(code[idx].jt, e.jt);
                ASSERT_EQ(code[idx].jf, e.jf);
                ASSERT_EQ(code[idx].k, e.k);

                idx++;
            }
        };

    lambda_gen_bpf_code_test(ip_bpf_code, filter::eProtocolID::Ip);
    lambda_gen_bpf_code_test(tcp_bpf_code, filter::eProtocolID::Tcp);
    lambda_gen_bpf_code_test(udp_bpf_code, filter::eProtocolID::Udp);
}

TEST(BPFapture, rule_of_X)
{  // ::bpfocket::bpfapture::core
    using namespace bpfapture;
    namespace bpfapture = ::bpfocket::bpfapture;

    auto lambda_constructor_destructor_test = [](bool promisc) {
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
            ASSERT_EQ(sockfd, sock_move.fd());
            ASSERT_EQ(ifname, sock_move.ifname());
            ASSERT_EQ(-1, fcntl(sock.fd(), F_GETFD));
            ASSERT_EQ(EBADF, errno);

            ASSERT_NE(ifname, sock.ifname());
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
            ASSERT_EQ(sockfd, sock_move_op.fd());
            ASSERT_EQ(ifname, sock_move_op.ifname());
            ASSERT_EQ(-1, fcntl(sock.fd(), F_GETFD));
            ASSERT_EQ(EBADF, errno);

            ASSERT_NE(ifname, sock.ifname());
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

    core::BPFapture sock{};
    sock.set_filter(filter::eProtocolID::Tcp);
    if (sock.err() != 0)
    {
        std::cerr << sock.err() << std::endl;
        return;
    }

    std::vector<struct sock_filter> filter_vec{
        filter::gen_bpf_code(filter::eProtocolID::Tcp) };
    
    struct sock_fprog filter{ sock.filter() };
    ASSERT_EQ(filter.len, filter_vec.size());
}

TEST(BPFapture, set_mtu)
{  // ::bpfocket::bpfapture::core
    /// set_mtu() is exec in constructor
    ///

    using namespace bpfapture;

    core::BPFapture sock{};
    int sockfd = sock.fd();

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
    sock.set_filter(filter::eProtocolID::Ip);
    //sock.set_filter(filter::eProtocolID::Tcp);
    //sock.set_filter(filter::eProtocolID::Udp);
    if (sock.err() != 0)
    {
        std::cerr << sock.err() << std::endl;
        return;
    }

    std::vector<uint8_t> buf(sock.mtu());
    ssize_t received_bytes = 0;

    int max_cnt = 10;
    while (true && max_cnt--)
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
