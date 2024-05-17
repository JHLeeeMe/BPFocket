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
#include <utility>    // std::pair<>

#define __BPFOCKET_BEGIN namespace bpfocket {
#define __BPFOCKET_END   }

__BPFOCKET_BEGIN

/// ============================================================================
/// Declarations
/// ============================================================================

namespace utils
{
    enum class eResultCode;

    [[noreturn]]
    void throwRuntimeError(eResultCode code,
                           const ssize_t err_no,
                           const std::string& caller_info,
                           const std::string& msg = "");
}  // ::bpfocket::utils

namespace filter
{

}  // ::bpfocket::filter

namespace core
{
    class RawSocket
    {
    public:  // rule of 5
        RawSocket(const bool promisc = false);
        ~RawSocket();

        RawSocket(const RawSocket&) = delete;
        RawSocket& operator=(const RawSocket&) = delete;

        RawSocket(RawSocket&&) = delete;
        RawSocket& operator=(RawSocket&&) = delete;
    public:
        auto fd()     const -> int;
        auto ifname() const -> std::string;
        auto err()    const -> ssize_t;

    private:
        auto create_fd()   -> utils::eResultCode;
        auto set_ifname()  -> utils::eResultCode;
        auto set_promisc() -> utils::eResultCode;
        auto set_ifflags(const int16_t flag) -> utils::eResultCode;
        auto get_ifflags()
                -> std::pair<utils::eResultCode, int16_t>;
        auto get_eth_ifr(const struct ifconf& ifc)
                -> std::pair<utils::eResultCode, struct ifreq>;
    private:
        int fd_;

        struct ifreq ifr_;
        std::string  ifname_;
        int16_t      ifflags_orig_;

        ssize_t err_;
    };
}  // ::bpfocket::core


/// ============================================================================
/// Definitions
/// ============================================================================

namespace utils
{
    enum class eResultCode
    {
        Success = 0,

        Failure           = 100,
        InterfaceNotFound = Failure + 1,  // 101

        IoctlFailureBase     = 200,
        IoctlGetConfigFailed = IoctlFailureBase + 1,  // 201
        IoctlGetFlagsFailed  = IoctlFailureBase + 2,  // 202
        IoctlSetFlagsFailed  = IoctlFailureBase + 3,  // 203
        IoctlGetHwAddrFailed = IoctlFailureBase + 4,  // 204

        SocketFailureBase    = 300,
        SocketCreationFailed = SocketFailureBase + 1,  // 301
        SocketSetOptFailed   = SocketFailureBase + 2,  // 302
    };

    [[noreturn]]
    void throwRuntimeError(eResultCode code,
                           const ssize_t err_no,
                           const std::string& caller_info,
                           const std::string& msg)
    {
        std::ostringstream oss{};
        oss << "Error occurred in " << caller_info << ":\n\t";

        if (!msg.empty())
        {
            oss << msg;
        }

        oss << " [code: " << static_cast<uint32_t>(code) << "]";

        if (err_no != 0)
        {
            oss << "[errno: " << err_no << "]";
        }

        throw std::runtime_error(oss.str());
    }
}  // ::bpfocket::utils

namespace filter
{

}  // ::bpfocket::filter

namespace core
{
    /// ========================================================================
    /// Rule of X
    /// ========================================================================

    RawSocket::RawSocket(const bool promisc)
        : fd_{ -1 }
        , ifr_{}
        , ifname_{}
        , ifflags_orig_{}
        , err_{}
    {
        utils::eResultCode code{};

        if ((code = create_fd()) != utils::eResultCode::Success)
        {
            utils::throwRuntimeError(code, err_, __FUNCTION__, "create_fd()");
        }

        try
        {
            if ((code = set_ifname()) != utils::eResultCode::Success)
            {
                utils::throwRuntimeError(
                    code, err_, __FUNCTION__, "set_ifname()");
            }

            std::pair<utils::eResultCode, int16_t> result{ get_ifflags() };
            if ((code = result.first) != utils::eResultCode::Success)
            {
                utils::throwRuntimeError(
                    code, err_, __FUNCTION__, "get_ifflags()");
            }

            ifflags_orig_ = result.second;

            if (promisc)
            {
                if ((code = set_promisc()) != utils::eResultCode::Success)
                {
                    utils::throwRuntimeError(
                        code, err_, __FUNCTION__, "set_promisc()");
                }
            }
        }
        catch (...)
        {
            close(fd_);
            throw;
        }
    }

    RawSocket::~RawSocket()
    {
        set_ifflags(ifflags_orig_);
        close(fd_);
    }


    /// ========================================================================
    /// Public Methods
    /// ========================================================================

    auto RawSocket::fd() const -> int
    {
        return fd_;
    }

    auto RawSocket::ifname() const -> std::string
    {
        return ifname_;
    }

    auto RawSocket::err() const -> ssize_t
    {
        return err_;
    }


    /// ========================================================================
    /// Private Methods
    /// ========================================================================

    auto RawSocket::create_fd() -> utils::eResultCode
    {
        fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd_ < 0)
        {
            err_ = errno;
            return utils::eResultCode::SocketCreationFailed;
        }

        return utils::eResultCode::Success;
    }

    auto RawSocket::set_ifname() -> utils::eResultCode
    {
        struct ifconf ifc{};

        if (::ioctl(fd_, SIOCGIFCONF, &ifc) < 0)
        {
            err_ = errno;
            return utils::eResultCode::IoctlGetConfigFailed;
        }

        std::vector<char> buf(ifc.ifc_len);
        ifc.ifc_buf = buf.data();

        if (::ioctl(fd_, SIOCGIFCONF, &ifc) < 0)
        {
            err_ = errno;
            return utils::eResultCode::IoctlGetConfigFailed;
        }

        std::pair<utils::eResultCode, struct ifreq> result{ get_eth_ifr(ifc) };
        if (result.first != utils::eResultCode::Success)
        {
            if (result.first == utils::eResultCode::InterfaceNotFound)
            {
                err_ = 0;
            }

            return result.first;
        }

        ifr_ = result.second;
        ifname_ = ifr_.ifr_name;

        return utils::eResultCode::Success;
    }

    auto RawSocket::get_eth_ifr(const struct ifconf& ifc)
            -> std::pair<utils::eResultCode, struct ifreq>
    {
        struct ifreq* ifr{ ifc.ifc_req };

        for (size_t i = 0; i < ifc.ifc_len / sizeof(struct ifreq); i++)
        {
            if (::ioctl(fd_, SIOCGIFFLAGS, &ifr[i]) < 0)
            {
                err_ = errno;
                return { utils::eResultCode::IoctlGetFlagsFailed, {} };
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
                return { utils::eResultCode::IoctlGetHwAddrFailed, {} };
            }

            if (ifr[i].ifr_hwaddr.sa_family != ARPHRD_ETHER)
            {
                continue;
            }

            const std::string eth_ifr_name{ ifr[i].ifr_name };
            if (eth_ifr_name.find("eth") != std::string::npos ||
                eth_ifr_name.find("en") != std::string::npos)
            {
                return { utils::eResultCode::Success, ifr[i] };
            }
        }

        return { utils::eResultCode::InterfaceNotFound, {} };
    }

    auto RawSocket::get_ifflags()
            -> std::pair<utils::eResultCode, int16_t>
    {
        struct ifreq ifr_tmp{ ifr_ };
        if (::ioctl(fd_, SIOCGIFFLAGS, &ifr_tmp) < 0)
        {
            err_ = errno;
            return { utils::eResultCode::IoctlGetFlagsFailed, {} };
        }

        return { utils::eResultCode::Success, ifr_tmp.ifr_flags };
    }

    auto RawSocket::set_ifflags(const int16_t flags) -> utils::eResultCode
    {
        ifr_.ifr_flags = flags;

        if (::ioctl(fd_, SIOCSIFFLAGS, &ifr_) < 0)
        {
            err_ = errno;
            return utils::eResultCode::IoctlSetFlagsFailed;
        }

        if (::setsockopt(fd_,
                         SOL_SOCKET,
                         SO_BINDTODEVICE,
                         ifname_.c_str(),
                         ifname_.length() + 1) < 0)
        {
            err_ = errno;
            return utils::eResultCode::SocketSetOptFailed;
        }

        return utils::eResultCode::Success;
    }

    auto RawSocket::set_promisc() -> utils::eResultCode
    {
        std::pair<utils::eResultCode, int16_t> result{ get_ifflags() };
        if (result.first != utils::eResultCode::Success)
        {
            return result.first;
        }

        return set_ifflags(result.second | IFF_PROMISC);
    }
}  // ::bpfocket::core
__BPFOCKET_END


#endif  // BPFOCKET_H
