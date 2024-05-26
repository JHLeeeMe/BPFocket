/// bpfapture_sample.cpp
///

#include <iostream>
#include <csignal>

#include "bpfocket.h"

int quit = 0;

void signal_handler(int)
{
    quit = 1;
}

int main()
{
    ::signal(SIGINT, &signal_handler);

    namespace utils  = bpfapture::utils;
    namespace filter = bpfapture::filter;
    namespace core   = bpfapture::core;

    // Create BPFapture
    const bool promisc = true;
    core::BPFapture sock{ promisc };

    // Set filter
    utils::eResultCode code{};
    code = sock.set_filter({ filter::eProtocolID::Icmp,
                             filter::eProtocolID::Tcp });
    if (code != utils::eResultCode::Success)
    {
        std::cerr <<
            "result code: " << static_cast<uint32_t>(code) << std::endl;
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
    while (!quit)
    {
        received_bytes = sock.receive(buf.data(), buf.size());
        if (received_bytes < 0)
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
