/// sysv_mq_test.cpp
///

#include "gtest/gtest.h"

#include "bpfocket.h"

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
