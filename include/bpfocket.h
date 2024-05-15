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
#include <optional>   // std::optional

#define __BPFOCKET_BEGIN namespace bpfocket {
#define __BPFOCKET_END   }

__BPFOCKET_BEGIN
namespace utils
{
    enum class eResultCode
    {
        Success = 0,

        Failure           = 100,
        IoctlFailed       = Failure + 1,  // 101
        InterfaceNotFound = Failure + 2,  // 102
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
        std::string ifname() const;
        const ssize_t err() const;

    private:
        const ssize_t create();
        utils::eResultCode set_ifname();
        auto find_eth_ifr(const struct ifconf& ifc)
            -> std::optional<struct ifreq>;
    private:
        int fd_;
        std::string ifname_;

        ssize_t err_;
    };

    RawSocket::RawSocket()
        : fd_{}
        , ifname_{}
        , err_{}
    {
        if (create() < 0)
        {
            std::runtime_error("To do");
        }

        if (set_ifname() != utils::eResultCode::Success)
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

    std::string RawSocket::ifname() const
    {
        return ifname_;
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

    utils::eResultCode RawSocket::set_ifname()
    {
        struct ifconf ifc{};

        if (::ioctl(fd_, SIOCGIFCONF, &ifc) < 0)
        {
            err_ = errno;
            return utils::eResultCode::IoctlFailed;
        }

        std::vector<char> buf{};
        buf.reserve(ifc.ifc_len);
        buf.resize(ifc.ifc_len);
        ifc.ifc_buf = buf.data();

        if (::ioctl(fd_, SIOCGIFCONF, &ifc) < 0)
        {
            err_ = errno;
            return utils::eResultCode::IoctlFailed;
        }

        std::optional<struct ifreq> result{ find_eth_ifr(ifc) };
        if (!result)
        {
            if (err_ == 0)  // interface not found.
            {
                return utils::eResultCode::InterfaceNotFound;
            }
            return utils::eResultCode::IoctlFailed;
        }

        struct ifreq eth_ifr{ result.value() };
        ifname_ = eth_ifr.ifr_name;

        return utils::eResultCode::Success;
    }

    auto RawSocket::find_eth_ifr(const struct ifconf& ifc)
        -> std::optional<struct ifreq>
    {
        err_ = 0;
        struct ifreq* ifr{ ifc.ifc_req };

        for (size_t i = 0; i < ifc.ifc_len / sizeof(struct ifreq); i++)
        {
            if (::ioctl(fd_, SIOCGIFFLAGS, &ifr[i]) < 0)
            {
                err_ = errno;
                return std::nullopt;
            }

            if ((ifr[i].ifr_flags & IFF_LOOPBACK) ||
                !(ifr[i].ifr_flags & IFF_UP) ||
                !(ifr[i].ifr_flags & IFF_RUNNING))
            {
                continue;
            }

            if (::ioctl(fd_, SIOCGIFHWADDR, &ifr[i]) < 0)
            {
                err_ = errno;
                return std::nullopt;
            }

            if (ifr[i].ifr_hwaddr.sa_family != ARPHRD_ETHER)
            {
                continue;
            }

            const std::string eth_ifr_name{ ifr[i].ifr_name };
            if (eth_ifr_name.find("eth") != std::string::npos ||
                eth_ifr_name.find("en") != std::string::npos)
            {
                return ifr[i];
            }
        }

        return std::nullopt;
    }
}  // ::bpfocket::core
__BPFOCKET_END


#endif  // BPFOCKET_H
