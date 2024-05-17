#ifndef BPFOCKET_H
#define BPFOCKET_H


#include <linux/filter.h>  // struct sock_filter
#include <sys/socket.h>
#include <sys/ioctl.h>     // ioctl()
#include <net/if.h>        // struct ifconf, struct ifreq 
#include <net/if_arp.h>    // ARPHDR_ETHER
#include <net/ethernet.h>  // ETH_P_ALL
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>    // htons()
#include <arpa/inet.h>     // inet_ntoa()
#include <unistd.h>        // close()

#include <stdexcept>  // runtime_error()
#include <utility>    // std::pair
#include <vector>     // std::vector

#define __BPFOCKET_BEGIN namespace bpfocket {
#define __BPFOCKET_END   }

__BPFOCKET_BEGIN

/// ============================================================================
/// Declarations
/// ============================================================================

namespace utils
{
    enum class eResultCode;
    enum class eProtocolID;

    [[noreturn]]
    void throwRuntimeError(eResultCode code,
                           const ssize_t err_no,
                           const std::string& caller_info,
                           const std::string& msg = "");

    auto gen_bpf_code(eProtocolID proto_id)
            -> std::vector<struct sock_filter>;
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
        auto set_filter(utils::eProtocolID proto_id) -> void;
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

        struct sock_fprog filter_;

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

    enum class eProtocolID
    {
        Ip = ETH_P_IP,
        Tcp = IPPROTO_TCP,
        Udp = IPPROTO_UDP,
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

    auto gen_bpf_code(eProtocolID proto_id)
            -> std::vector<struct sock_filter>
    {
        std::vector<struct sock_filter> bpf_code{};

        bpf_code.push_back(
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                     offsetof(struct ether_header, ether_type)));

        if (proto_id == eProtocolID::Ip)
        {
            bpf_code.push_back(
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 1));
        }
        else  // Tcp or Udp
        {
            bpf_code.push_back(
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 0, 3));
            bpf_code.push_back(
                BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
                        ETH_HLEN + offsetof(struct iphdr, protocol)));
            bpf_code.push_back(
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                        static_cast<uint16_t>(proto_id), 0, 1));
        }

        bpf_code.push_back(BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF));
        bpf_code.push_back(BPF_STMT(BPF_RET + BPF_K, 0x00));

        return bpf_code;
    }
}  // ::bpfocket::utils

namespace filter
{

}  // ::bpfocket::filter

namespace core
{
    /// ========================================================================
    /// RawSocket Rule of X
    /// ========================================================================

    RawSocket::RawSocket(const bool promisc)
        : fd_{ -1 }
        , ifr_{}
        , ifname_{}
        , ifflags_orig_{}
        , filter_{}
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
    /// RawSocket Public Methods
    /// ========================================================================

    auto RawSocket::set_filter(utils::eProtocolID proto_id) -> void
    {
        err_ = 0;

        std::vector<struct sock_filter> bpf_code{
            utils::gen_bpf_code(proto_id) };

        filter_.len = bpf_code.size();
        filter_.filter = bpf_code.data();

        if (::setsockopt(fd_,
                         SOL_SOCKET,
                         SO_ATTACH_FILTER,
                         &filter_,
                         sizeof(filter_)) < 0)
        {
            err_ = errno;
        }
    }

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
    /// RawSocket Private Methods
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
