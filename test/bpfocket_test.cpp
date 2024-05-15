/// sysv_mq_test.cpp
///

#include "gtest/gtest.h"

#include "bpfocket.h"

TEST(core, RawSocket)
{  // ::bpfocket::core
    using namespace ::bpfocket;

    core::RawSocket sockfd{};
    ASSERT_EQ(typeid(sockfd), typeid(core::RawSocket));
}
