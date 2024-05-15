#ifndef BPFOCKET_H
#define BPFOCKET_H


#include <sys/ioctl.h>     // ioctl()
#include <sys/socket.h>    // socket()
#include <net/if.h>        // struct ifconf, struct ifreq 
#include <net/if_arp.h>    // ARPHDR_ETHER
#include <net/ethernet.h>  // ETH_P_ALL
#include <netinet/in.h>    // htons()
#include <unistd.h>        // close()

#include <stdexcept>  // runtime_error()

#define __BPFOCKET_BEGIN namespace bpfocket {
#define __BPFOCKET_END   }

__BPFOCKET_BEGIN
namespace utils
{
    enum class eResultCode
    {
        Success = 0,
        Failure = 10,
    };
}  // ::bpfocket::utils

namespace filter
{

}  // ::bpfocket::filter

namespace core
{
    class RawSocket
    {
    public:  // rule of 5
        RawSocket();
        ~RawSocket();

        RawSocket(const RawSocket&) = delete;
        RawSocket& operator=(const RawSocket&) = delete;

        RawSocket(RawSocket&&) = delete;
        RawSocket& operator=(RawSocket&&) = delete;
    public:
        const int fd() const;
        const ssize_t err() const;

    private:
        const ssize_t create();
    private:
        int fd_;

        ssize_t err_;
    };

    RawSocket::RawSocket()
        : fd_{}
        , err_{}
    {
        if (create() < 0)
        {
            std::runtime_error("To do");
        }
    }

    RawSocket::~RawSocket()
    {
        close(fd_);
    }

    const int RawSocket::fd() const
    {
        return fd_;
    }

    const ssize_t RawSocket::err() const
    {
        return err_;
    }

    const ssize_t RawSocket::create()
    {
        fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd_ < 0)
        {
            err_ = errno;
            return -1;
        }

        return 0;
    }
}  // ::bpfocket::core
__BPFOCKET_END


#endif  // BPFOCKET_H
