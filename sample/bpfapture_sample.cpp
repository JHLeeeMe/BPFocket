/// bpfapture_sample.cpp
///

#include <iostream>

#include "bpfocket.h"

int main()
{
    namespace utils  = bpfapture::utils;
    namespace filter = bpfapture::filter;
    namespace core   = bpfapture::core;

    // Create BPFapture
    const bool promisc = true;
    core::BPFapture sock{ promisc };

    // Set filter
    std::vector<filter::eProtocolID> proto_ids{ filter::eProtocolID::Icmp,
                                                filter::eProtocolID::Tcp, };
    utils::eResultCode code{};
    if ((code = sock.set_filter(proto_ids)) != utils::eResultCode::Success)
    {
        std::cerr << "result code: "<< static_cast<uint32_t>(code) << std::endl;
        if (sock.err() != 0)
        {
            std::cerr << "errno: " << sock.err() << std::endl;
        }

        return 1;
    }

    // Create buffer (mtu size)
    std::vector<uint8_t> buf(sock.mtu());
    ssize_t received_bytes = 0;

    int max_cnt = 10;
    while (true && max_cnt--)
    {
        if ((received_bytes = sock.receive(buf.data(), buf.size())) < 0)
        {
            std::cerr << sock.err() << std::endl;
            return 2;
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

    return 0;
}
