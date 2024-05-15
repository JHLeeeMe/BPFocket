/// bpfocket_test.cpp
///

#include "gtest/gtest.h"

#include "bpfocket.h"

TEST(sys, ioctl)
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

TEST(utils, eResultCode)
{  // ::bpfocket::utils
    using namespace ::bpfocket;

    ASSERT_EQ(0, static_cast<int>(utils::eResultCode::Success));
    ASSERT_EQ(10, static_cast<int>(utils::eResultCode::Failure));
}

TEST(core, RawSocket)
{  // ::bpfocket::core
    using namespace ::bpfocket;

    core::RawSocket sockfd{};
    ASSERT_EQ(typeid(sockfd), typeid(core::RawSocket));

    {  /// Compile error
        /// copy constructor
        // core::RawSocket sockfd_copy{ sockfd };

        /// copy operator
        // core::RawSocket sockfd_copy_op{};
        // sockfd_copy_op = sockfd;

        /// move constructor
        // core::RawSocket sockfd_move{ std::move(sockfd) };

        /// move operator
        // core::RawSocket sockfd_move_op{};
        // sockfd_move_op = std::move(sockfd);
    }

    {  // err()
        ASSERT_EQ(0, sockfd.err());
    }
}
