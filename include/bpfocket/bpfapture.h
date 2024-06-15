/// ============================================================================
/// bpfapture.h
/// ----------------------------------------------------------------------------
/// linux packet capture header-only library using berkely packet filter
///
/// ----------------------------------------------------------------------------
/// Code Structure
/// ----------------------------------------------------------------------------
/// namespace bpfocket
/// {
/// namespace bpfapture
/// {
///     // Declarations
///     namespace utils { ... }
///     namespace filter { ... }
///     namespace core { ... }
///
///     // Implementation
///     namespace utils { ... }
///     namespace filter { ... }
///     namespace core
///     {
///         inline BPFapture::xxx { ... };
///         ...
///     }
/// }
/// }
/// namespace bpfapture = ::bpfocket::bpfapture;
///
/// ----------------------------------------------------------------------------
/// License: The Unlicense <https://unlicense.org/>
/// ============================================================================

#ifndef BPFAPTURE_H
#define BPFAPTURE_H


#include <linux/filter.h>  // struct sock_filter
#include <sys/socket.h>
#include <sys/ioctl.h>     // ioctl()
#include <net/if.h>        // struct ifconf, struct ifreq
#include <net/if_arp.h>    // ARPHDR_ETHER
#include <net/ethernet.h>  // ETH_P_ALL
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/in.h>    // htons()
#include <arpa/inet.h>     // inet_ntoa()
#include <unistd.h>        // close()

#include <cstdint>    // uint*_t
#include <cstring>    // strnlen()
#include <stdexcept>  // std::runtime_error()
#include <sstream>    // std::ostringstream()
#include <utility>    // std::pair
#include <vector>     // std::vector
#include <set>        // std::set

#define __BPFOCKET_BEGIN namespace bpfocket {
#define __BPFOCKET_END   }

__BPFOCKET_BEGIN
namespace bpfapture
{

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
}  // ::bpfocket::bpfapture::utils

namespace filter
{
    enum class eProtocolID;

    auto gen_bpf_code(const std::vector<eProtocolID>& proto_ids)
            -> std::vector<struct sock_filter>;
}  // ::bpfocket::bpfapture::filter

namespace core
{
    class BPFapture
    {
    public:  // rule of 5
        BPFapture(const bool promisc = false);
        ~BPFapture();

        BPFapture(const BPFapture&) = delete;
        BPFapture& operator=(const BPFapture&) = delete;

        BPFapture(BPFapture&& other) noexcept;
        BPFapture& operator=(BPFapture&& other) noexcept;
    public:
        auto set_filter(const std::vector<filter::eProtocolID>& proto_ids)
                -> utils::eResultCode;
        auto receive(void* buf, const size_t buf_len) -> ssize_t;
        auto fd()      const -> int;
        auto ifname()  const -> std::string;
        auto mtu()     const -> int;
        auto filter()  const -> struct sock_fprog;
        auto err()     const -> ssize_t;

    private:
        auto create_fd()      -> utils::eResultCode;
        auto set_ifname()     -> utils::eResultCode;
        auto bind_to_device() -> utils::eResultCode;
        auto set_mtu()        -> utils::eResultCode;
        auto set_promisc()    -> utils::eResultCode;
        auto set_ifflags(const int16_t flags) -> utils::eResultCode;
        auto get_ifflags()
                -> std::pair<utils::eResultCode, int16_t>;
        auto get_eth_ifr(const struct ifconf& ifc)
                -> std::pair<utils::eResultCode, struct ifreq>;
    private:
        int fd_;
        struct ifreq ifr_;
        int mtu_;
        struct sock_fprog filter_;
        ssize_t err_;

        static int16_t& s_ifflags_orig_ref()
        {
            static int16_t s_ifflags_orig_ = -1;
            return s_ifflags_orig_;
        }
    };
}  // ::bpfocket::bpfapture::core


/// ============================================================================
/// Implementation
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
        IoctlSetMtuFailed    = IoctlFailureBase + 5,  // 205

        SocketFailureBase    = 300,
        SocketCreationFailed = SocketFailureBase + 1,  // 301
        SocketSetOptFailed   = SocketFailureBase + 2,  // 302
        SocketReceiveFailed  = SocketFailureBase + 3,  // 303
    };

    [[noreturn]]
    inline void throwRuntimeError(eResultCode code,
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
}  // ::bpfocket::bpfapture::utils

namespace filter
{
    enum class eProtocolID
    {
        Ip   = ETH_P_IP,
        Icmp = IPPROTO_ICMP,
        Tcp  = IPPROTO_TCP,
        Udp  = IPPROTO_UDP,
    };

    inline auto gen_bpf_code(const std::vector<eProtocolID>& proto_ids)
            -> std::vector<struct sock_filter>
    {
        if (proto_ids.empty())
        {
            return {};
        }

        std::vector<struct sock_filter> bpf_code{};

        std::set<eProtocolID> unique_proto_ids{ proto_ids.begin(),
                                                proto_ids.end() };
        size_t unique_proto_ids_len = unique_proto_ids.size();

        bpf_code.push_back(
            BPF_STMT(BPF_LD + BPF_H + BPF_ABS,
                     offsetof(struct ether_header, ether_type)));

        bpf_code.push_back(BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETH_P_IP, 1, 0));
        bpf_code.push_back(BPF_STMT(BPF_RET + BPF_K, 0x00));

        if (*unique_proto_ids.begin() == eProtocolID::Ip &&
            unique_proto_ids_len == 1)
        {
            bpf_code.push_back(BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF));

            return bpf_code;
        }

        bpf_code.push_back(
            BPF_STMT(BPF_LD + BPF_B + BPF_ABS,
                     ETHER_HDR_LEN + offsetof(struct iphdr, protocol)));

        if (unique_proto_ids.find(eProtocolID::Ip) != unique_proto_ids.end())
        {
            unique_proto_ids_len--;
        }

        size_t idx = 0;
        for (const auto& proto_id : unique_proto_ids)
        {
            if (proto_id == eProtocolID::Ip)
            {
                continue;
            }

            bpf_code.push_back(
                BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K,
                         static_cast<uint16_t>(proto_id),
                         static_cast<uint8_t>(unique_proto_ids_len - idx),
                         0));
            idx++;
        }

        bpf_code.push_back(BPF_STMT(BPF_RET + BPF_K, 0x00));
        bpf_code.push_back(BPF_STMT(BPF_RET + BPF_K, 0xFFFFFFFF));

        return bpf_code;
    }
}  // ::bpfocket::bpfapture::filter

namespace core
{
    /// ========================================================================
    /// BPFapture Rule of X
    /// ========================================================================

    inline BPFapture::BPFapture(const bool promisc)
        : fd_{ -1 }
        , ifr_{}
        , mtu_{}
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

            if ((code = bind_to_device()) != utils::eResultCode::Success)
            {
                utils::throwRuntimeError(
                    code, err_, __FUNCTION__, "bind_to_device()");
            }

            if ((code = set_mtu()) != utils::eResultCode::Success)
            {
                utils::throwRuntimeError(code, err_, __FUNCTION__, "set_mtu()");
            }

            if (s_ifflags_orig_ref() == -1)
            {
                std::pair<utils::eResultCode, int16_t> result{ get_ifflags() };
                if ((code = result.first) != utils::eResultCode::Success)
                {
                    utils::throwRuntimeError(
                        code, err_, __FUNCTION__, "get_ifflags()");
                }

                s_ifflags_orig_ref() = result.second;
            }

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

    inline BPFapture::~BPFapture()
    {
        if (fd_ == -1)
        {
            return;
        }

        set_ifflags(s_ifflags_orig_ref());
        close(fd_);
    }

    inline BPFapture::BPFapture(BPFapture&& other) noexcept
        : fd_{ other.fd_ }
        , ifr_{ other.ifr_ }
        , mtu_{ other.mtu_ }
        , filter_{ other.filter_ }
        , err_{ other.err_ }
    {
        other.fd_ = -1;
        other.err_ = 0;
    }

    inline BPFapture& BPFapture::operator=(BPFapture&& other) noexcept
    {
        if (this != &other)
        {
            fd_ = other.fd_;
            ifr_ = other.ifr_;
            mtu_ = other.mtu_;
            filter_ = other.filter_;
            err_ = other.err_;

            other.fd_ = -1;
            other.err_ = 0;
        }

        return *this;
    }


    /// ========================================================================
    /// BPFapture Public Methods
    /// ========================================================================

    inline auto BPFapture::set_filter(
        const std::vector<filter::eProtocolID>& proto_ids) -> utils::eResultCode
    {
        err_ = 0;

        std::vector<struct sock_filter> bpf_code{
            filter::gen_bpf_code(proto_ids) };
        if (bpf_code.empty())
        {
            return utils::eResultCode::Failure;
        }

        filter_.len = bpf_code.size();
        filter_.filter = bpf_code.data();

        if (::setsockopt(fd_,
                         SOL_SOCKET,
                         SO_ATTACH_FILTER,
                         &filter_,
                         sizeof(filter_)) < 0)
        {
            err_ = errno;
            return utils::eResultCode::SocketSetOptFailed;
        }

        return utils::eResultCode::Success;
    }

    inline auto BPFapture::receive(void* buf, const size_t buf_len) -> ssize_t
    {
        ssize_t received_bytes =
            ::recvfrom(fd_, buf, buf_len, 0, nullptr, nullptr);
        if (received_bytes < 0)
        {
            err_ = errno;
        }

        return received_bytes;
    }

    inline auto BPFapture::fd() const -> int
    {
        return fd_;
    }

    inline auto BPFapture::ifname() const -> std::string
    {
        return ifr_.ifr_name;
    }

    inline auto BPFapture::mtu() const -> int
    {
        return mtu_;
    }

    inline auto BPFapture::filter() const -> struct sock_fprog
    {
        return filter_;
    }

    inline auto BPFapture::err() const -> ssize_t
    {
        return err_;
    }


    /// ========================================================================
    /// BPFapture Private Methods
    /// ========================================================================

    inline auto BPFapture::create_fd() -> utils::eResultCode
    {
        fd_ = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd_ < 0)
        {
            err_ = errno;
            return utils::eResultCode::SocketCreationFailed;
        }

        return utils::eResultCode::Success;
    }

    inline auto BPFapture::set_ifname() -> utils::eResultCode
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

        return utils::eResultCode::Success;
    }

    inline auto BPFapture::bind_to_device() -> utils::eResultCode
    {
        if (::setsockopt(fd_,
                         SOL_SOCKET,
                         SO_BINDTODEVICE,
                         ifr_.ifr_name,
                         strnlen(ifr_.ifr_name, IFNAMSIZ) + 1) < 0)
        {
            err_ = errno;
            return utils::eResultCode::SocketSetOptFailed;
        }

        return utils::eResultCode::Success;
    }

    inline auto BPFapture::set_mtu() -> utils::eResultCode
    {
        struct ifreq ifr_tmp{ ifr_ };
        if (::ioctl(fd_, SIOCGIFMTU, &ifr_tmp) < 0)
        {
            err_ = errno;
            return utils::eResultCode::IoctlSetMtuFailed;
        }

        mtu_ = ifr_tmp.ifr_mtu;

        return utils::eResultCode::Success;
    }

    inline auto BPFapture::set_promisc() -> utils::eResultCode
    {
        std::pair<utils::eResultCode, int16_t> result{ get_ifflags() };
        if (result.first != utils::eResultCode::Success)
        {
            return result.first;
        }

        return set_ifflags(result.second | IFF_PROMISC);
    }

    inline auto BPFapture::set_ifflags(const int16_t flags) -> utils::eResultCode
    {
        ifr_.ifr_flags = flags;

        if (::ioctl(fd_, SIOCSIFFLAGS, &ifr_) < 0)
        {
            err_ = errno;
            return utils::eResultCode::IoctlSetFlagsFailed;
        }

        return utils::eResultCode::Success;
    }

    inline auto BPFapture::get_ifflags()
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

    inline auto BPFapture::get_eth_ifr(const struct ifconf& ifc)
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
}  // ::bpfocket::bpfapture::core

}  // ::bpfocket::bpfapture
__BPFOCKET_END


/// ============================================================================
/// namespace alias
/// ============================================================================

namespace bpfapture = ::bpfocket::bpfapture;


#endif  // BPFAPTURE_H
