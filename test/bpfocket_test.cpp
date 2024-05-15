/// bpfocket_test.cpp
///

#include <fcntl.h>  // fcntl()

#include "gtest/gtest.h"

#include "bpfocket.h"

TEST(ioctl, SIOCGIFCONF)
{  // ::ioctl
    using namespace ::bpfocket;

    core::RawSocket sock{};
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

    core::RawSocket sock{};
    ASSERT_EQ(typeid(sock), typeid(core::RawSocket));

    errno = 0;
    int fd_tmp{};
    { // destructor
        core::RawSocket sock_tmp{};
        fd_tmp = sock_tmp.fd();
        ASSERT_NE(0, fd_tmp);
        ASSERT_NE(-1, fcntl(fd_tmp, F_GETFD));
        ASSERT_NE(EBADF, errno);
    }
    ASSERT_EQ(-1, fcntl(fd_tmp, F_GETFD));
    ASSERT_EQ(EBADF, errno);

    {  /// Compile error
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

    {  // err()
        ASSERT_EQ(0, sock.err());
    }
}

TEST(RawSocket, set_ifname)
{  // ::bpfocket::core
    using namespace ::bpfocket;

    core::RawSocket sock{};
    ASSERT_NE(std::string(), sock.ifname());
}
