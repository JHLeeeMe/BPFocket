/// bpfocket_test.cpp
///

#include <fcntl.h>  // fcntl()

#include "gtest/gtest.h"

#include "bpfocket.h"

TEST(ioctl, getconf)
{  // ::ioctl
    using namespace ::bpfocket;

    core::RawSocket sock{ false };
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

TEST(RawSocket, rule_of_X)
{  // ::bpfocket::core
    using namespace ::bpfocket;

    auto lambda_constructor_destructor_test = [](bool promisc) {
        core::RawSocket sock{ promisc };
        ASSERT_EQ(typeid(sock), typeid(core::RawSocket));

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
            core::RawSocket sock_tmp{ promisc };
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

    {  // Compile error
        /// copy constructor
        // core::RawSocket sock_copy{ sockfd };
        /// copy assignment operator
        // core::RawSocket sock_copy_op{};
        // sock_copy_op = sock;

        /// move constructor
        // core::RawSocket sock_move{ std::move(sock) };
        /// move assignment operator
        // core::RawSocket sock_move_op{};
        // sock_move_op = std::move(sock);
    }
}

TEST(RawSocket, set_ifname)
{  // ::bpfocket::core
    /// set_ifname() is exec in constructor
    ///

    using namespace ::bpfocket;

    core::RawSocket sock{ false };
    ASSERT_NE(std::string(), sock.ifname());
}

TEST(throwRuntimeError, all)
{  // ::bpfocket::utils
    using namespace ::bpfocket;

    ssize_t err_no = 1;

    ASSERT_THROW(
        utils::throwRuntimeError(
            utils::eResultCode::Failure, err_no, __FUNCTION__),
        std::runtime_error
    );
}
