// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

#include "pal_config.h"
#include "pal_networking.h"
#include "pal_utilities.h"

#include <stdlib.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <vector>

#if HAVE_ALLOCA_H
#include <alloca.h>
#endif

#if !defined(IPV6_ADD_MEMBERSHIP) && defined(IPV6_JOIN_GROUP)
#define IPV6_ADD_MEMBERSHIP IPV6_JOIN_GROUP
#endif

#if !defined(IPV6_DROP_MEMBERSHIP) && defined(IPV6_LEAVE_GROUP)
#define IPV6_DROP_MEMBERSHIP IPV6_LEAVE_GROUP
#endif

const int INET6_ADDRSTRLEN_MANAGED = 65; // The C# code has a longer max string length

static_assert(PAL_HOST_NOT_FOUND == HOST_NOT_FOUND, "");
static_assert(PAL_TRY_AGAIN == TRY_AGAIN, "");
static_assert(PAL_NO_RECOVERY == NO_RECOVERY, "");
static_assert(PAL_NO_DATA == NO_DATA, "");
static_assert(PAL_NO_ADDRESS == NO_ADDRESS, "");
static_assert(sizeof(uint8_t) == sizeof(char), ""); // We make casts from uint8_t to char so make sure it's legal

// NOTE: clang has trouble with offsetof nested inside of static_assert. Instead, store
//       the necessary field offsets in constants.
const int OffsetOfIOVectorBase = offsetof(IOVector, Base);
const int OffsetOfIOVectorCount = offsetof(IOVector, Count);
const int OffsetOfIovecBase = offsetof(iovec, iov_base);
const int OffsetOfIovecLen = offsetof(iovec, iov_len);

// We require that IOVector have the same layout as iovec.
static_assert(sizeof(IOVector) == sizeof(iovec), "");
static_assert(sizeof(decltype(IOVector::Base)) == sizeof(decltype(iovec::iov_base)), "");
static_assert(OffsetOfIOVectorBase == OffsetOfIovecBase, "");
static_assert(sizeof(decltype(IOVector::Count)) == sizeof(decltype(iovec::iov_len)), "");
static_assert(OffsetOfIOVectorCount == OffsetOfIovecLen, "");

// We require that FDSET_MAX_FDS is less than or equal to FD_SETSIZE.
static_assert(PAL_FDSET_MAX_FDS <= FD_SETSIZE, "");

template <typename T>
static T Min(T left, T right)
{
    return left < right ? left : right;
}

static int IpStringToAddressHelper(const uint8_t* address, const uint8_t* port, bool isIPv6, addrinfo*& info)
{
    assert(address != nullptr);

    addrinfo hint = {.ai_family = isIPv6 ? AF_INET6 : AF_INET, .ai_flags = AI_NUMERICHOST | AI_NUMERICSERV};

    info = nullptr;
    return getaddrinfo(reinterpret_cast<const char*>(address), reinterpret_cast<const char*>(port), &hint, &info);
}

static void ConvertByteArrayToIn6Addr(in6_addr& addr, const uint8_t* buffer, int32_t bufferLength)
{
#if HAVE_IN6_U
    assert(bufferLength == ARRAY_SIZE(addr.__in6_u.__u6_addr8));
    memcpy(addr.__in6_u.__u6_addr8, buffer, UnsignedCast(bufferLength));
#else
    assert(bufferLength == ARRAY_SIZE(addr.__u6_addr.__u6_addr8));
    memcpy(addr.__u6_addr.__u6_addr8, buffer, UnsignedCast(bufferLength));
#endif
}

static void ConvertIn6AddrToByteArray(uint8_t* buffer, int32_t bufferLength, const in6_addr& addr)
{
#if HAVE_IN6_U
    assert(bufferLength == ARRAY_SIZE(addr.__in6_u.__u6_addr8));
    memcpy(buffer, addr.__in6_u.__u6_addr8, UnsignedCast(bufferLength));
#else
    assert(bufferLength == ARRAY_SIZE(addr.__u6_addr.__u6_addr8));
    memcpy(buffer, addr.__u6_addr.__u6_addr8, UnsignedCast(bufferLength));
#endif
}

static void ConvertByteArrayToV6SockAddrIn(sockaddr_in6& addr, const uint8_t* buffer, int32_t bufferLength)
{
    ConvertByteArrayToIn6Addr(addr.sin6_addr, buffer, bufferLength);

    // Mark that this is INET6
    addr.sin6_family = AF_INET6;
}

static void ConvertByteArrayToSockAddrIn(sockaddr_in& addr, const uint8_t* buffer, int32_t bufferLength)
{
    assert(bufferLength == NUM_BYTES_IN_IPV4_ADDRESS);
    (void)bufferLength; // Silence compiler warnings about unused variables on release mode

    addr.sin_addr.s_addr = *reinterpret_cast<const uint32_t*>(buffer); // The address comes as network byte order
    addr.sin_family = AF_INET;
}

static void ConvertInAddrToByteArray(uint8_t* buffer, int32_t bufferLength, const in_addr& addr)
{
    assert(bufferLength == NUM_BYTES_IN_IPV4_ADDRESS);
    (void)bufferLength; // Silence compiler warnings about unused variables on release mode

    *reinterpret_cast<uint32_t*>(buffer) = addr.s_addr; // Send back in network byte order.
}

static int32_t ConvertGetAddrInfoAndGetNameInfoErrorsToPal(int32_t error)
{
    switch (error)
    {
        case 0:
            return 0;
        case EAI_AGAIN:
            return PAL_EAI_AGAIN;
        case EAI_BADFLAGS:
            return PAL_EAI_BADFLAGS;
#ifdef EAI_FAIL
        case EAI_FAIL:
            return PAL_EAI_FAIL;
#endif
        case EAI_FAMILY:
            return PAL_EAI_FAMILY;
        case EAI_NONAME:
#ifdef EAI_NODATA
        case EAI_NODATA:
#endif
            return PAL_EAI_NONAME;
    }

    assert(false && "Unknown AddrInfo error flag");
    return -1;
}

extern "C" int32_t
IPv6StringToAddress(const uint8_t* address, const uint8_t* port, uint8_t* buffer, int32_t bufferLength, uint32_t* scope)
{
    assert(buffer != nullptr);
    assert(bufferLength == NUM_BYTES_IN_IPV6_ADDRESS);
    assert(scope != nullptr);

    // Call our helper to do the getaddrinfo call for us; once we have the info, copy what we need
    addrinfo* info;
    int32_t result = IpStringToAddressHelper(address, port, true, info);
    if (result == 0)
    {
        sockaddr_in6* addr = reinterpret_cast<sockaddr_in6*>(info->ai_addr);
        ConvertIn6AddrToByteArray(buffer, bufferLength, addr->sin6_addr);
        *scope = addr->sin6_scope_id;

        freeaddrinfo(info);
    }

    return ConvertGetAddrInfoAndGetNameInfoErrorsToPal(result);
}

extern "C" int32_t IPv4StringToAddress(const uint8_t* address, uint8_t* buffer, int32_t bufferLength, uint16_t* port)
{
    assert(buffer != nullptr);
    assert(bufferLength == NUM_BYTES_IN_IPV4_ADDRESS);
    assert(port != nullptr);

    // Call our helper to do the getaddrinfo call for us; once we have the info, copy what we need
    addrinfo* info;
    int32_t result = IpStringToAddressHelper(address, nullptr, false, info);
    if (result == 0)
    {
        sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(info->ai_addr);
        ConvertInAddrToByteArray(buffer, bufferLength, addr->sin_addr);
        *port = addr->sin_port;

        freeaddrinfo(info);
    }

    return ConvertGetAddrInfoAndGetNameInfoErrorsToPal(result);
}

extern "C" int32_t IPAddressToString(const uint8_t* address,
                                     int32_t addressLength,
                                     bool isIPv6,
                                     uint8_t* string,
                                     int32_t stringLength,
                                     uint32_t scope /* = 0*/)
{
    assert(address != nullptr);
    assert((addressLength == NUM_BYTES_IN_IPV6_ADDRESS) || (addressLength == NUM_BYTES_IN_IPV4_ADDRESS));
    assert(string != nullptr);

    // These constants differ per platform so the managed side uses the bigger value; therefore, check that
    // the length is between the two lengths
    assert((stringLength >= INET_ADDRSTRLEN) && (stringLength <= INET6_ADDRSTRLEN_MANAGED));
    (void)addressLength;            // Silence compiler warnings about unused variables on release mode
    (void)INET6_ADDRSTRLEN_MANAGED; // Silence compiler warnings about unused variables on release mode

    int32_t result;
    socklen_t len = UnsignedCast(stringLength);

    if (isIPv6)
    {
        sockaddr_in6 addr = {.sin6_scope_id = scope};

        ConvertByteArrayToV6SockAddrIn(addr, address, addressLength);
        result = getnameinfo(reinterpret_cast<const sockaddr*>(&addr),
                             sizeof(sockaddr_in6),
                             reinterpret_cast<char*>(string),
                             len,
                             nullptr,
                             0,
                             NI_NUMERICHOST);
    }
    else
    {
        sockaddr_in addr = {};
        ConvertByteArrayToSockAddrIn(addr, address, addressLength);
        result = getnameinfo(reinterpret_cast<const sockaddr*>(&addr),
                             sizeof(sockaddr_in),
                             reinterpret_cast<char*>(string),
                             len,
                             nullptr,
                             0,
                             NI_NUMERICHOST);
    }

    return ConvertGetAddrInfoAndGetNameInfoErrorsToPal(result);
}

extern "C" int32_t GetHostEntryForName(const uint8_t* address, HostEntry* entry)
{
    if (address == nullptr || entry == nullptr)
    {
        return PAL_EAI_BADARG;
    }

    // Get all address families and the canonical name
    addrinfo hint = {.ai_family = AF_UNSPEC, .ai_flags = AI_CANONNAME};

    addrinfo* info = nullptr;
    int result = getaddrinfo(reinterpret_cast<const char*>(address), nullptr, &hint, &info);
    if (result != 0)
    {
        return ConvertGetAddrInfoAndGetNameInfoErrorsToPal(result);
    }

    *entry = {.CanonicalName = nullptr, .AddressListHandle = reinterpret_cast<void*>(info), .IPAddressCount = 0};

    // Find the canonical name for this host (if any) and count the number of IP end points.
    for (addrinfo* ai = info; ai != nullptr; ai = ai->ai_next)
    {
        // If we haven't found a canonical name yet and this addrinfo has one, copy it
        if ((entry->CanonicalName == nullptr) && (ai->ai_canonname != nullptr))
        {
            entry->CanonicalName = reinterpret_cast<uint8_t*>(ai->ai_canonname);
        }

        if (ai->ai_family == AF_INET || ai->ai_family == AF_INET6)
        {
            entry->IPAddressCount++;
        }
    }

    return PAL_EAI_SUCCESS;
}

extern "C" int32_t GetNextIPAddress(void** addressListHandle, IPAddress* endPoint)
{
    if (addressListHandle == nullptr || endPoint == nullptr)
    {
        return PAL_EAI_BADARG;
    }

    auto* ai = reinterpret_cast<addrinfo*>(*addressListHandle);
    for (; ai != nullptr; ai = ai->ai_next)
    {
        switch (ai->ai_family)
        {
            case AF_INET:
            {
                auto* inetSockAddr = reinterpret_cast<sockaddr_in*>(ai->ai_addr);

                ConvertInAddrToByteArray(endPoint->Address, NUM_BYTES_IN_IPV4_ADDRESS, inetSockAddr->sin_addr);
                endPoint->IsIPv6 = 0;
                break;
            }

            case AF_INET6:
            {
                auto* inet6SockAddr = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);

                ConvertIn6AddrToByteArray(endPoint->Address, NUM_BYTES_IN_IPV6_ADDRESS, inet6SockAddr->sin6_addr);
                endPoint->IsIPv6 = 1;
                endPoint->ScopeId = inet6SockAddr->sin6_scope_id;
                break;
            }

            default:
                // Skip non-IPv4 and non-IPv6 addresses
                continue;
        }

        *addressListHandle = reinterpret_cast<void*>(ai->ai_next);
        return PAL_EAI_SUCCESS;
    }

    return PAL_EAI_NOMORE;
}

extern "C" void FreeHostEntry(HostEntry* entry)
{
    if (entry != nullptr)
    {
        auto* ai = reinterpret_cast<addrinfo*>(entry->AddressListHandle);
        freeaddrinfo(ai);
    }
}

inline int32_t ConvertGetNameInfoFlagsToPal(int32_t flags)
{
    int32_t outFlags = 0;
    if ((flags & NI_NAMEREQD) == NI_NAMEREQD)
    {
        outFlags |= PAL_NI_NAMEREQD;
    }
    if ((flags & NI_NUMERICHOST) == NI_NUMERICHOST)
    {
        outFlags |= PAL_NI_NUMERICHOST;
    }

    return outFlags;
}

extern "C" int32_t GetNameInfo(const uint8_t* address,
                               int32_t addressLength,
                               bool isIPv6,
                               uint8_t* host,
                               int32_t hostLength,
                               uint8_t* service,
                               int32_t serviceLength,
                               int32_t flags)
{
    assert(address != nullptr);
    assert(addressLength > 0);
    assert((host != nullptr) || (service != nullptr));
    assert((hostLength > 0) || (serviceLength > 0));

    int32_t nativeFlags = ConvertGetNameInfoFlagsToPal(flags);
    int32_t result;

    if (isIPv6)
    {
        sockaddr_in6 addr = {};
        ConvertByteArrayToV6SockAddrIn(addr, address, addressLength);
        result = getnameinfo(reinterpret_cast<const sockaddr*>(&addr),
                             sizeof(sockaddr_in6),
                             reinterpret_cast<char*>(host),
                             UnsignedCast(hostLength),
                             reinterpret_cast<char*>(service),
                             UnsignedCast(serviceLength),
                             nativeFlags);
    }
    else
    {
        sockaddr_in addr = {};
        ConvertByteArrayToSockAddrIn(addr, address, addressLength);
        result = getnameinfo(reinterpret_cast<const sockaddr*>(&addr),
                             sizeof(sockaddr_in),
                             reinterpret_cast<char*>(host),
                             UnsignedCast(hostLength),
                             reinterpret_cast<char*>(service),
                             UnsignedCast(serviceLength),
                             nativeFlags);
    }

    return ConvertGetAddrInfoAndGetNameInfoErrorsToPal(result);
}

extern "C" int32_t GetHostName(uint8_t* name, int32_t nameLength)
{
    assert(name != nullptr);
    assert(nameLength > 0);

    size_t unsignedSize = UnsignedCast(nameLength);
    return gethostname(reinterpret_cast<char*>(name), unsignedSize);
}

template <typename TType, typename TField>
static bool IsInBounds(const TType* base, size_t len, const TField* value)
{
    auto* baseAddr = reinterpret_cast<const uint8_t*>(base);
    auto* valueAddr = reinterpret_cast<const uint8_t*>(value);
    return valueAddr >= baseAddr && (valueAddr + sizeof(TField)) <= (baseAddr + len);
}

extern "C" Error GetIPSocketAddressSizes(int32_t* ipv4SocketAddressSize, int32_t* ipv6SocketAddressSize)
{
    if (ipv4SocketAddressSize == nullptr || ipv6SocketAddressSize == nullptr)
    {
        return PAL_EFAULT;
    }

    *ipv4SocketAddressSize = sizeof(sockaddr_in);
    *ipv6SocketAddressSize = sizeof(sockaddr_in6);
    return PAL_SUCCESS;
}

static bool TryConvertAddressFamilyPlatformToPal(sa_family_t platformAddressFamily, int32_t* palAddressFamily)
{
    assert(palAddressFamily != nullptr);

    switch (platformAddressFamily)
    {
        case AF_UNSPEC:
            *palAddressFamily = PAL_AF_UNSPEC;
            return true;

        case AF_UNIX:
            *palAddressFamily = PAL_AF_UNIX;
            return true;

        case AF_INET:
            *palAddressFamily = PAL_AF_INET;
            return true;

        case AF_INET6:
            *palAddressFamily = PAL_AF_INET6;
            return true;

        default:
            *palAddressFamily = platformAddressFamily;
            return false;
    }
}

static bool TryConvertAddressFamilyPalToPlatform(int32_t palAddressFamily, sa_family_t* platformAddressFamily)
{
    assert(platformAddressFamily != nullptr);

    switch (palAddressFamily)
    {
        case PAL_AF_UNSPEC:
            *platformAddressFamily = AF_UNSPEC;
            return true;

        case PAL_AF_UNIX:
            *platformAddressFamily = AF_UNIX;
            return true;

        case PAL_AF_INET:
            *platformAddressFamily = AF_INET;
            return true;

        case PAL_AF_INET6:
            *platformAddressFamily = AF_INET6;
            return true;

        default:
            *platformAddressFamily = static_cast<sa_family_t>(palAddressFamily);
            return false;
    }
}

extern "C" Error GetAddressFamily(const uint8_t* socketAddress, int32_t socketAddressLen, int32_t* addressFamily)
{
    if (socketAddress == nullptr || addressFamily == nullptr || socketAddressLen < 0)
    {
        return PAL_EFAULT;
    }

    auto* sockAddr = reinterpret_cast<const sockaddr*>(socketAddress);
    if (!IsInBounds(sockAddr, static_cast<size_t>(socketAddressLen), &sockAddr->sa_family))
    {
        return PAL_EFAULT;
    }

    if (!TryConvertAddressFamilyPlatformToPal(sockAddr->sa_family, addressFamily))
    {
        // TODO: we may want to let the address family through transparently if it's
        //       outside the range of shimmed values.
        return PAL_EAFNOSUPPORT;
    }

    return PAL_SUCCESS;
}

extern "C" Error SetAddressFamily(uint8_t* socketAddress, int32_t socketAddressLen, int32_t addressFamily)
{
    auto* sockAddr = reinterpret_cast<sockaddr*>(socketAddress);
    if (sockAddr == nullptr || socketAddressLen < 0 ||
        !IsInBounds(sockAddr, static_cast<size_t>(socketAddressLen), &sockAddr->sa_family))
    {
        return PAL_EFAULT;
    }

    if (!TryConvertAddressFamilyPalToPlatform(addressFamily, &sockAddr->sa_family))
    {
        // TODO: we may want to let the address family through transparently if it's
        //       outside the range of shimmed values.
        return PAL_EAFNOSUPPORT;
    }

    return PAL_SUCCESS;
}

extern "C" Error GetPort(const uint8_t* socketAddress, int32_t socketAddressLen, uint16_t* port)
{
    if (socketAddress == nullptr)
    {
        return PAL_EFAULT;
    }

    auto* sockAddr = reinterpret_cast<const sockaddr*>(socketAddress);
    if (!IsInBounds(sockAddr, static_cast<size_t>(socketAddressLen), &sockAddr->sa_family))
    {
        return PAL_EFAULT;
    }

    switch (sockAddr->sa_family)
    {
        case AF_INET:
        {
            if (socketAddressLen < 0 || static_cast<size_t>(socketAddressLen) < sizeof(sockaddr_in))
            {
                return PAL_EFAULT;
            }

            *port = ntohs(reinterpret_cast<const sockaddr_in*>(socketAddress)->sin_port);
            return PAL_SUCCESS;
        }

        case AF_INET6:
        {
            if (socketAddressLen < 0 || static_cast<size_t>(socketAddressLen) < sizeof(sockaddr_in6))
            {
                return PAL_EFAULT;
            }

            *port = ntohs(reinterpret_cast<const sockaddr_in6*>(socketAddress)->sin6_port);
            return PAL_SUCCESS;
        }

        default:
            return PAL_EAFNOSUPPORT;
    }
}

extern "C" Error SetPort(uint8_t* socketAddress, int32_t socketAddressLen, uint16_t port)
{
    if (socketAddress == nullptr)
    {
        return PAL_EFAULT;
    }

    auto* sockAddr = reinterpret_cast<const sockaddr*>(socketAddress);
    if (!IsInBounds(sockAddr, static_cast<size_t>(socketAddressLen), &sockAddr->sa_family))
    {
        return PAL_EFAULT;
    }

    switch (sockAddr->sa_family)
    {
        case AF_INET:
        {
            if (socketAddressLen < 0 || static_cast<size_t>(socketAddressLen) < sizeof(sockaddr_in))
            {
                return PAL_EFAULT;
            }

            reinterpret_cast<sockaddr_in*>(socketAddress)->sin_port = htons(port);
            return PAL_SUCCESS;
        }

        case AF_INET6:
        {
            if (socketAddressLen < 0 || static_cast<size_t>(socketAddressLen) < sizeof(sockaddr_in6))
            {
                return PAL_EFAULT;
            }

            reinterpret_cast<sockaddr_in6*>(socketAddress)->sin6_port = htons(port);
            return PAL_SUCCESS;
        }

        default:
            return PAL_EAFNOSUPPORT;
    }
}

extern "C" Error GetIPv4Address(const uint8_t* socketAddress, int32_t socketAddressLen, uint32_t* address)
{
    if (socketAddress == nullptr || address == nullptr || socketAddressLen < 0 ||
        static_cast<size_t>(socketAddressLen) < sizeof(sockaddr_in))
    {
        return PAL_EFAULT;
    }

    auto* sockAddr = reinterpret_cast<const sockaddr*>(socketAddress);
    if (!IsInBounds(sockAddr, static_cast<size_t>(socketAddressLen), &sockAddr->sa_family))
    {
        return PAL_EFAULT;
    }

    if (sockAddr->sa_family != AF_INET)
    {
        return PAL_EINVAL;
    }

    *address = reinterpret_cast<const sockaddr_in*>(socketAddress)->sin_addr.s_addr;
    return PAL_SUCCESS;
}

extern "C" Error SetIPv4Address(uint8_t* socketAddress, int32_t socketAddressLen, uint32_t address)
{
    if (socketAddress == nullptr || socketAddressLen < 0 || static_cast<size_t>(socketAddressLen) < sizeof(sockaddr_in))
    {
        return PAL_EFAULT;
    }

    auto* sockAddr = reinterpret_cast<sockaddr*>(socketAddress);
    if (!IsInBounds(sockAddr, static_cast<size_t>(socketAddressLen), &sockAddr->sa_family))
    {
        return PAL_EFAULT;
    }

    if (sockAddr->sa_family != AF_INET)
    {
        return PAL_EINVAL;
    }

    auto* inetSockAddr = reinterpret_cast<sockaddr_in*>(sockAddr);

    inetSockAddr->sin_family = AF_INET;
    inetSockAddr->sin_addr.s_addr = address;
    return PAL_SUCCESS;
}

extern "C" Error GetIPv6Address(
    const uint8_t* socketAddress, int32_t socketAddressLen, uint8_t* address, int32_t addressLen, uint32_t* scopeId)
{
    if (socketAddress == nullptr || address == nullptr || scopeId == nullptr || socketAddressLen < 0 ||
        static_cast<size_t>(socketAddressLen) < sizeof(sockaddr_in6) || addressLen < NUM_BYTES_IN_IPV6_ADDRESS)
    {
        return PAL_EFAULT;
    }

    auto* sockAddr = reinterpret_cast<const sockaddr*>(socketAddress);
    if (!IsInBounds(sockAddr, static_cast<size_t>(socketAddressLen), &sockAddr->sa_family))
    {
        return PAL_EFAULT;
    }

    if (sockAddr->sa_family != AF_INET6)
    {
        return PAL_EINVAL;
    }

    auto* inet6SockAddr = reinterpret_cast<const sockaddr_in6*>(sockAddr);
    ConvertIn6AddrToByteArray(address, addressLen, inet6SockAddr->sin6_addr);
    *scopeId = inet6SockAddr->sin6_scope_id;

    return PAL_SUCCESS;
}

extern "C" Error
SetIPv6Address(uint8_t* socketAddress, int32_t socketAddressLen, uint8_t* address, int32_t addressLen, uint32_t scopeId)
{
    if (socketAddress == nullptr || address == nullptr || socketAddressLen < 0 ||
        static_cast<size_t>(socketAddressLen) < sizeof(sockaddr_in6) || addressLen < NUM_BYTES_IN_IPV6_ADDRESS)
    {
        return PAL_EFAULT;
    }

    auto* sockAddr = reinterpret_cast<sockaddr*>(socketAddress);
    if (!IsInBounds(sockAddr, static_cast<size_t>(socketAddressLen), &sockAddr->sa_family))
    {
        return PAL_EFAULT;
    }

    if (sockAddr->sa_family != AF_INET6)
    {
        return PAL_EINVAL;
    }

    auto* inet6SockAddr = reinterpret_cast<sockaddr_in6*>(sockAddr);
    ConvertByteArrayToV6SockAddrIn(*inet6SockAddr, address, addressLen);
    inet6SockAddr->sin6_family = AF_INET6;
    inet6SockAddr->sin6_flowinfo = 0;
    inet6SockAddr->sin6_scope_id = scopeId;

    return PAL_SUCCESS;
}

static void ConvertMessageHeaderToMsghdr(msghdr* header, const MessageHeader& messageHeader)
{
    *header = {
        .msg_name = messageHeader.SocketAddress,
        .msg_namelen = static_cast<unsigned int>(messageHeader.SocketAddressLen),
        .msg_iov = reinterpret_cast<iovec*>(messageHeader.IOVectors),
        .msg_iovlen = static_cast<decltype(header->msg_iovlen)>(messageHeader.IOVectorCount),
        .msg_control = messageHeader.ControlBuffer,
        .msg_controllen = static_cast<decltype(header->msg_controllen)>(messageHeader.ControlBufferLen),
    };
}

extern "C" int32_t GetControlMessageBufferSize(int32_t isIPv4, int32_t isIPv6)
{
    // Note: it is possible that the address family of the socket is neither
    //       AF_INET nor AF_INET6. In this case both inputs will be false and
    //       the controll message buffer size should be zero.
    return (isIPv4 != 0 ? CMSG_SPACE(sizeof(in_pktinfo)) : 0) + (isIPv6 != 0 ? CMSG_SPACE(sizeof(in6_pktinfo)) : 0);
}

static int32_t GetIPv4PacketInformation(cmsghdr* controlMessage, IPPacketInformation* packetInfo)
{
    assert(controlMessage != nullptr);
    assert(packetInfo != nullptr);

    if (controlMessage->cmsg_len < sizeof(in_pktinfo))
    {
        assert(false && "expected a control message large enough to hold an in_pktinfo value");
        return 0;
    }

    auto* pktinfo = reinterpret_cast<in_pktinfo*>(CMSG_DATA(controlMessage));
    ConvertInAddrToByteArray(&packetInfo->Address.Address[0], NUM_BYTES_IN_IPV4_ADDRESS, pktinfo->ipi_addr);
    packetInfo->InterfaceIndex = static_cast<int32_t>(pktinfo->ipi_ifindex);

    return 1;
}

static int32_t GetIPv6PacketInformation(cmsghdr* controlMessage, IPPacketInformation* packetInfo)
{
    assert(controlMessage != nullptr);
    assert(packetInfo != nullptr);

    if (controlMessage->cmsg_len < sizeof(in6_pktinfo))
    {
        assert(false && "expected a control message large enough to hold an in6_pktinfo value");
        return 0;
    }

    auto* pktinfo = reinterpret_cast<in6_pktinfo*>(CMSG_DATA(controlMessage));
    ConvertIn6AddrToByteArray(&packetInfo->Address.Address[0], NUM_BYTES_IN_IPV6_ADDRESS, pktinfo->ipi6_addr);
    packetInfo->Address.IsIPv6 = 1;
    packetInfo->InterfaceIndex = static_cast<int32_t>(pktinfo->ipi6_ifindex);

    return 1;
}

extern "C" int32_t
TryGetIPPacketInformation(MessageHeader* messageHeader, int32_t isIPv4, IPPacketInformation* packetInfo)
{
    if (messageHeader == nullptr || packetInfo == nullptr)
    {
        return 0;
    }

    msghdr header;
    ConvertMessageHeaderToMsghdr(&header, *messageHeader);

    cmsghdr* controlMessage = CMSG_FIRSTHDR(&header);
    if (isIPv4 != 0)
    {
        for (; controlMessage != nullptr; controlMessage = CMSG_NXTHDR(&header, controlMessage))
        {
            if (controlMessage->cmsg_level == IPPROTO_IP && controlMessage->cmsg_type == IP_PKTINFO)
            {
                return GetIPv4PacketInformation(controlMessage, packetInfo);
            }
        }
    }
    else
    {
        for (; controlMessage != nullptr; controlMessage = CMSG_NXTHDR(&header, controlMessage))
        {
            if (controlMessage->cmsg_level == IPPROTO_IPV6 && controlMessage->cmsg_type == IPV6_PKTINFO)
            {
                return GetIPv6PacketInformation(controlMessage, packetInfo);
            }
        }
    }

    return 0;
}

static bool GetMulticastOptionName(int32_t multicastOption, bool isIPv6, int& optionName)
{
    switch (multicastOption)
    {
        case PAL_MULTICAST_ADD:
            optionName = isIPv6 ? IPV6_ADD_MEMBERSHIP : IP_ADD_MEMBERSHIP;
            return true;

        case PAL_MULTICAST_DROP:
            optionName = isIPv6 ? IPV6_DROP_MEMBERSHIP : IP_DROP_MEMBERSHIP;
            return true;

        default:
            return false;
    }
}

extern "C" Error GetIPv4MulticastOption(int32_t socket, int32_t multicastOption, IPv4MulticastOption* option)
{
    if (option == nullptr)
    {
        return PAL_EFAULT;
    }

    int optionName;
    if (!GetMulticastOptionName(multicastOption, false, optionName))
    {
        return PAL_EINVAL;
    }

    ip_mreqn opt;
    socklen_t len = sizeof(opt);
    int err = getsockopt(socket, IPPROTO_IP, optionName, &opt, &len);
    if (err != 0)
    {
        return ConvertErrorPlatformToPal(errno);
    }

    *option = {.MulticastAddress = opt.imr_multiaddr.s_addr,
               .LocalAddress = opt.imr_address.s_addr,
               .InterfaceIndex = opt.imr_ifindex};
    return PAL_SUCCESS;
}

extern "C" Error SetIPv4MulticastOption(int32_t socket, int32_t multicastOption, IPv4MulticastOption* option)
{
    if (option == nullptr)
    {
        return PAL_EFAULT;
    }

    int optionName;
    if (!GetMulticastOptionName(multicastOption, false, optionName))
    {
        return PAL_EINVAL;
    }

    ip_mreqn opt = {.imr_multiaddr = {.s_addr = option->MulticastAddress},
                    .imr_address = {.s_addr = option->LocalAddress},
                    .imr_ifindex = option->InterfaceIndex};
    int err = setsockopt(socket, IPPROTO_IP, optionName, &opt, sizeof(opt));
    return err == 0 ? PAL_SUCCESS : ConvertErrorPlatformToPal(errno);
}

extern "C" Error GetIPv6MulticastOption(int32_t socket, int32_t multicastOption, IPv6MulticastOption* option)
{
    if (option == nullptr)
    {
        return PAL_EFAULT;
    }

    int optionName;
    if (!GetMulticastOptionName(multicastOption, false, optionName))
    {
        return PAL_EINVAL;
    }

    ipv6_mreq opt;
    socklen_t len = sizeof(opt);
    int err = getsockopt(socket, IPPROTO_IP, optionName, &opt, &len);
    if (err != 0)
    {
        return ConvertErrorPlatformToPal(errno);
    }

    ConvertIn6AddrToByteArray(&option->Address.Address[0], NUM_BYTES_IN_IPV6_ADDRESS, opt.ipv6mr_multiaddr);
    option->InterfaceIndex = static_cast<int32_t>(opt.ipv6mr_interface);
    return PAL_SUCCESS;
}

extern "C" Error SetIPv6MulticastOption(int32_t socket, int32_t multicastOption, IPv6MulticastOption* option)
{
    if (option == nullptr)
    {
        return PAL_EFAULT;
    }

    int optionName;
    if (!GetMulticastOptionName(multicastOption, false, optionName))
    {
        return PAL_EINVAL;
    }

    ipv6_mreq opt = {.ipv6mr_interface = static_cast<unsigned int>(option->InterfaceIndex)};
    ConvertByteArrayToIn6Addr(opt.ipv6mr_multiaddr, &option->Address.Address[0], NUM_BYTES_IN_IPV6_ADDRESS);

    int err = setsockopt(socket, IPPROTO_IP, optionName, &opt, sizeof(opt));
    return err == 0 ? PAL_SUCCESS : ConvertErrorPlatformToPal(errno);
}

extern "C" Error GetLingerOption(int32_t socket, LingerOption* option)
{
    if (option == nullptr)
    {
        return PAL_EFAULT;
    }

    linger opt;
    socklen_t len = sizeof(opt);
    int err = getsockopt(socket, SOL_SOCKET, SO_LINGER, &opt, &len);
    if (err != 0)
    {
        return ConvertErrorPlatformToPal(errno);
    }

    *option = {.OnOff = opt.l_onoff, .Seconds = opt.l_linger};
    return PAL_SUCCESS;
}

extern "C" Error SetLingerOption(int32_t socket, LingerOption* option)
{
    if (option == nullptr)
    {
        return PAL_EFAULT;
    }

    linger opt = {.l_onoff = option->OnOff, .l_linger = option->Seconds};
    int err = setsockopt(socket, SOL_SOCKET, SO_LINGER, &opt, sizeof(opt));
    return err == 0 ? PAL_SUCCESS : ConvertErrorPlatformToPal(errno);
}

static bool ConvertSocketFlagsPalToPlatform(int32_t palFlags, int& platformFlags)
{
    const int32_t SupportedFlagsMask = PAL_MSG_OOB |
        PAL_MSG_PEEK |
        PAL_MSG_DONTROUTE |
        PAL_MSG_TRUNC |
        PAL_MSG_CTRUNC;

    if ((palFlags & ~SupportedFlagsMask) != 0)
    {
        // TODO: we may want to simply mask off unsupported flags.
        return false;
    }

    platformFlags = ((palFlags & PAL_MSG_OOB) == 0 ? 0 : MSG_OOB) |
        ((palFlags & PAL_MSG_PEEK) == 0 ? 0 : MSG_PEEK) |
        ((palFlags & PAL_MSG_DONTROUTE) == 0 ? 0 : MSG_DONTROUTE) |
        ((palFlags & PAL_MSG_TRUNC) == 0 ? 0 : MSG_TRUNC) |
        ((palFlags & PAL_MSG_CTRUNC) == 0 ? 0 : MSG_CTRUNC);

    return true;
}

static int32_t ConvertSocketFlagsPlatformToPal(int platformFlags)
{
    const int SupportedFlagsMask = MSG_OOB |
        MSG_PEEK |
        MSG_DONTROUTE |
        MSG_TRUNC |
        MSG_CTRUNC;

    platformFlags &= SupportedFlagsMask;

    return ((platformFlags & MSG_OOB) == 0 ? 0 : PAL_MSG_OOB) |
        ((platformFlags & MSG_PEEK) == 0 ? 0 : PAL_MSG_PEEK) |
        ((platformFlags & MSG_DONTROUTE) == 0 ? 0 : PAL_MSG_DONTROUTE) |
        ((platformFlags & MSG_TRUNC) == 0 ? 0 : PAL_MSG_TRUNC) |
        ((platformFlags & MSG_CTRUNC) == 0 ? 0 : PAL_MSG_CTRUNC);
}

extern "C" Error ReceiveMessage(int32_t socket, MessageHeader* messageHeader, int32_t flags, int64_t* received)
{
    if (messageHeader == nullptr || received == nullptr || messageHeader->SocketAddressLen < 0 ||
        messageHeader->ControlBufferLen < 0 || messageHeader->IOVectorCount < 0)
    {
        return PAL_EFAULT;
    }

    int socketFlags;
    if (!ConvertSocketFlagsPalToPlatform(flags, socketFlags))
    {
        return PAL_ENOTSUP;
    }

    msghdr header;
    ConvertMessageHeaderToMsghdr(&header, *messageHeader);

    ssize_t res = recvmsg(socket, &header, socketFlags);

    assert(static_cast<int32_t>(header.msg_namelen) <= messageHeader->SocketAddressLen);
    messageHeader->SocketAddressLen = Min(static_cast<int32_t>(header.msg_namelen), messageHeader->SocketAddressLen);
    memcpy(messageHeader->SocketAddress, header.msg_name, static_cast<size_t>(messageHeader->SocketAddressLen));

    assert(header.msg_controllen <= static_cast<size_t>(messageHeader->ControlBufferLen));
    messageHeader->ControlBufferLen = Min(static_cast<int32_t>(header.msg_controllen), messageHeader->ControlBufferLen);
    memcpy(messageHeader->ControlBuffer, header.msg_control, static_cast<size_t>(messageHeader->ControlBufferLen));

    messageHeader->Flags = ConvertSocketFlagsPlatformToPal(header.msg_flags);

    if (res != -1)
    {
        *received = res;
        return PAL_SUCCESS;
    }

    *received = 0;
    return ConvertErrorPlatformToPal(errno);
}

extern "C" Error SendMessage(int32_t socket, MessageHeader* messageHeader, int32_t flags, int64_t* sent)
{
    if (messageHeader == nullptr || sent == nullptr || messageHeader->SocketAddressLen < 0 ||
        messageHeader->ControlBufferLen < 0 || messageHeader->IOVectorCount < 0)
    {
        return PAL_EFAULT;
    }

    int socketFlags;
    if (!ConvertSocketFlagsPalToPlatform(flags, socketFlags))
    {
        return PAL_ENOTSUP;
    }

    msghdr header;
    ConvertMessageHeaderToMsghdr(&header, *messageHeader);

    ssize_t res = sendmsg(socket, &header, flags);
    if (res != -1)
    {
        *sent = res;
        return PAL_SUCCESS;
    }

    *sent = 0;
    return ConvertErrorPlatformToPal(errno);
}

extern "C" Error Accept(int32_t socket, uint8_t* socketAddress, int32_t* socketAddressLen, int32_t* acceptedSocket)
{
    if (socketAddress == nullptr || socketAddressLen == nullptr || acceptedSocket == nullptr || *socketAddressLen < 0)
    {
        return PAL_EFAULT;
    }

    socklen_t addrLen = static_cast<socklen_t>(*socketAddressLen);
    int accepted = accept(socket, reinterpret_cast<sockaddr*>(socketAddress), &addrLen);
    if (accepted == -1)
    {
        *acceptedSocket = -1;
        return ConvertErrorPlatformToPal(errno);
    }

    assert(addrLen <= static_cast<socklen_t>(*socketAddressLen));
    *socketAddressLen = static_cast<int32_t>(addrLen);
    *acceptedSocket = accepted;
    return PAL_SUCCESS;
}

extern "C" Error Bind(int32_t socket, uint8_t* socketAddress, int32_t socketAddressLen)
{
    if (socketAddress == nullptr || socketAddressLen < 0)
    {
        return PAL_EFAULT;
    }

    int err = bind(socket, reinterpret_cast<sockaddr*>(socketAddress), static_cast<socklen_t>(socketAddressLen));
    return err == 0 ? PAL_SUCCESS : ConvertErrorPlatformToPal(errno);
}

extern "C" Error Connect(int32_t socket, uint8_t* socketAddress, int32_t socketAddressLen)
{
    if (socketAddress == nullptr || socketAddressLen < 0)
    {
        return PAL_EFAULT;
    }

    int err = connect(socket, reinterpret_cast<sockaddr*>(socketAddress), static_cast<socklen_t>(socketAddressLen));
    return err == 0 ? PAL_SUCCESS : ConvertErrorPlatformToPal(errno);
}

extern "C" Error GetPeerName(int32_t socket, uint8_t* socketAddress, int32_t* socketAddressLen)
{
    if (socketAddress == nullptr || socketAddressLen == nullptr || *socketAddressLen < 0)
    {
        return PAL_EFAULT;
    }

    socklen_t addrLen = static_cast<socklen_t>(*socketAddressLen);
    int err = getpeername(socket, reinterpret_cast<sockaddr*>(socketAddress), &addrLen);
    if (err != 0)
    {
        return ConvertErrorPlatformToPal(errno);
    }

    assert(addrLen <= static_cast<socklen_t>(*socketAddressLen));
    *socketAddressLen = static_cast<int32_t>(addrLen);
    return PAL_SUCCESS;
}

extern "C" Error GetSockName(int32_t socket, uint8_t* socketAddress, int32_t* socketAddressLen)
{
    if (socketAddress == nullptr || socketAddressLen == nullptr || *socketAddressLen < 0)
    {
        return PAL_EFAULT;
    }

    socklen_t addrLen = static_cast<socklen_t>(*socketAddressLen);
    int err = getsockname(socket, reinterpret_cast<sockaddr*>(socketAddress), &addrLen);
    if (err != 0)
    {
        return ConvertErrorPlatformToPal(errno);
    }

    assert(addrLen <= static_cast<socklen_t>(*socketAddressLen));
    *socketAddressLen = static_cast<int32_t>(addrLen);
    return PAL_SUCCESS;
}

extern "C" Error Listen(int32_t socket, int32_t backlog)
{
    int err = listen(socket, backlog);
    return err == 0 ? PAL_SUCCESS : ConvertErrorPlatformToPal(errno);
}

extern "C" Error Shutdown(int32_t socket, int32_t socketShutdown)
{
    int how;
    switch (socketShutdown)
    {
        case PAL_SHUT_READ:
            how = SHUT_RD;
            break;

        case PAL_SHUT_WRITE:
            how = SHUT_WR;
            break;

        case PAL_SHUT_BOTH:
            how = SHUT_RDWR;
            break;

        default:
            return PAL_EINVAL;
    }

    int err = shutdown(socket, how);
    return err == 0 ? PAL_SUCCESS : ConvertErrorPlatformToPal(errno);
}

extern "C" Error GetSocketErrorOption(int32_t socket, Error* error)
{
    if (error == nullptr)
    {
        return PAL_EFAULT;
    }

    int socketErrno;
    socklen_t optLen = sizeof(socketErrno);
    int err = getsockopt(socket, SOL_SOCKET, SO_ERROR, &socketErrno, &optLen);
    if (err != 0)
    {
        return ConvertErrorPlatformToPal(errno);
    }

    assert(optLen == sizeof(socketErrno));
    *error = ConvertErrorPlatformToPal(socketErrno);
    return PAL_SUCCESS;
}

static bool TryGetPlatformSocketOption(int32_t socketOptionName, int32_t socketOptionLevel, int& optLevel, int& optName)
{
    switch (socketOptionName)
    {
        case PAL_SOL_SOCKET:
            optLevel = SOL_SOCKET;

            switch (socketOptionLevel)
            {
                case PAL_SO_DEBUG:
                    optName = SO_DEBUG;
                    return true;

                case PAL_SO_ACCEPTCONN:
                    optName = SO_ACCEPTCONN;
                    return true;

                case PAL_SO_REUSEADDR:
                    optName = SO_REUSEADDR;
                    return true;

                case PAL_SO_KEEPALIVE:
                    optName = SO_KEEPALIVE;
                    return true;

                case PAL_SO_DONTROUTE:
                    optName = SO_DONTROUTE;
                    return true;

                case PAL_SO_BROADCAST:
                    optName = SO_BROADCAST;
                    return true;

                // case PAL_SO_USELOOPBACK:

                case PAL_SO_LINGER:
                    optName = SO_LINGER;
                    return true;

                case PAL_SO_OOBINLINE:
                    optName = SO_OOBINLINE;
                    return true;

                // case PAL_SO_DONTLINGER:

                // case PAL_SO_EXCLUSIVEADDRUSE:

                case PAL_SO_SNDBUF:
                    optName = SO_SNDBUF;
                    return true;

                case PAL_SO_RCVBUF:
                    optName = SO_RCVBUF;
                    return true;

                case PAL_SO_SNDLOWAT:
                    optName = SO_SNDLOWAT;
                    return true;

                case PAL_SO_RCVLOWAT:
                    optName = SO_RCVLOWAT;
                    return true;

                case PAL_SO_SNDTIMEO:
                    optName = SO_SNDTIMEO;
                    return true;

                case PAL_SO_RCVTIMEO:
                    optName = SO_RCVTIMEO;
                    return true;

                case PAL_SO_ERROR:
                    optName = SO_ERROR;
                    return true;

                case PAL_SO_TYPE:
                    optName = SO_TYPE;
                    return true;

                // case PAL_SO_MAXCONN:

                default:
                    return false;
            }

        case PAL_SOL_IP:
            optLevel = IPPROTO_IP;

            switch (socketOptionLevel)
            {
                case PAL_SO_IP_OPTIONS:
                    optName = IP_OPTIONS;
                    return true;

                case PAL_SO_IP_HDRINCL:
                    optName = IP_HDRINCL;
                    return true;

                case PAL_SO_IP_TOS:
                    optName = IP_TOS;
                    return true;

                case PAL_SO_IP_TTL:
                    optName = IP_TTL;
                    return true;

                case PAL_SO_IP_MULTICAST_IF:
                    optName = IP_MULTICAST_IF;
                    return true;

                case PAL_SO_IP_MULTICAST_TTL:
                    optName = IP_MULTICAST_TTL;
                    return true;

                case PAL_SO_IP_MULTICAST_LOOP:
                    optName = IP_MULTICAST_LOOP;
                    return true;

                case PAL_SO_IP_ADD_MEMBERSHIP:
                    optName = IP_ADD_MEMBERSHIP;
                    return true;

                case PAL_SO_IP_DROP_MEMBERSHIP:
                    optName = IP_DROP_MEMBERSHIP;
                    return true;

                // case PAL_SO_IP_DONTFRAGMENT:

                case PAL_SO_IP_ADD_SOURCE_MEMBERSHIP:
                    optName = IP_ADD_SOURCE_MEMBERSHIP;
                    return true;

                case PAL_SO_IP_DROP_SOURCE_MEMBERSHIP:
                    optName = IP_DROP_SOURCE_MEMBERSHIP;
                    return true;

                case PAL_SO_IP_BLOCK_SOURCE:
                    optName = IP_BLOCK_SOURCE;
                    return true;

                case PAL_SO_IP_UNBLOCK_SOURCE:
                    optName = IP_UNBLOCK_SOURCE;
                    return true;

                case PAL_SO_IP_PKTINFO:
                    optName = IP_PKTINFO;
                    return true;

                default:
                    return false;
            }

        case PAL_SOL_IPV6:
            optLevel = IPPROTO_IPV6;

            switch (socketOptionLevel)
            {
                case PAL_SO_IPV6_HOPLIMIT:
                    optName = IPV6_HOPLIMIT;
                    return true;

                // case PAL_SO_IPV6_PROTECTION_LEVEL:

                case PAL_SO_IPV6_V6ONLY:
                    optName = IPV6_V6ONLY;
                    return true;

                case PAL_SO_IP_PKTINFO:
                    optName = IPV6_RECVPKTINFO;
                    return true;

                default:
                    return false;
            }

        case PAL_SOL_TCP:
            optLevel = IPPROTO_TCP;

            switch (socketOptionLevel)
            {
                case PAL_SO_TCP_NODELAY:
                    optName = TCP_NODELAY;
                    return true;

                // case PAL_SO_TCP_BSDURGENT:

                default:
                    return false;
            }

        case PAL_SOL_UDP:
            optLevel = IPPROTO_UDP;

            switch (socketOptionLevel)
            {
                // case PAL_SO_UDP_NOCHECKSUM:

                // case PAL_SO_UDP_CHECKSUM_COVERAGE:

                // case PAL_SO_UDP_UPDATEACCEPTCONTEXT:

                // case PAL_SO_UDP_UPDATECONNECTCONTEXT:

                default:
                    return false;
            }

        default:
            return false;
    }
}

extern "C" Error GetSockOpt(int32_t socket, int32_t socketOptionLevel, int32_t socketOptionName, uint8_t* optionValue, int32_t* optionLen)
{
    if (optionLen == nullptr || *optionLen < 0)
    {
        return PAL_EFAULT;
    }

    int optLevel, optName;
    if (!TryGetPlatformSocketOption(socketOptionLevel, socketOptionName, optLevel, optName))
    {
        return PAL_ENOTSUP;
    }

    auto optLen = static_cast<socklen_t>(*optionLen);
    int err = getsockopt(socket, optLevel, optName, optionValue, &optLen);
    if (err != 0)
    {
        return ConvertErrorPlatformToPal(errno);
    }

    assert(optLen <= static_cast<socklen_t>(*optionLen));
    *optionLen = static_cast<int32_t>(optLen);
    return PAL_SUCCESS;
}

extern "C" Error SetSockOpt(int32_t socket, int32_t socketOptionLevel, int32_t socketOptionName, uint8_t* optionValue, int32_t optionLen)
{
    if (optionLen < 0)
    {
        return PAL_EFAULT;
    }

    int optLevel, optName;
    if (!TryGetPlatformSocketOption(socketOptionLevel, socketOptionName, optLevel, optName))
    {
        return PAL_ENOTSUP;
    }

    int err = setsockopt(socket, optLevel, optName, optionValue, static_cast<socklen_t>(optionLen));
    return err == 0 ? PAL_SUCCESS : ConvertErrorPlatformToPal(errno);
}

static bool TryConvertSocketTypePalToPlatform(int32_t palSocketType, int* platformSocketType)
{
    assert(platformSocketType != nullptr);

    switch (palSocketType)
    {
        case PAL_SOCK_STREAM:
           *platformSocketType = SOCK_STREAM;
            return true;

        case PAL_SOCK_DGRAM:
            *platformSocketType = SOCK_DGRAM;
            return true;

        case PAL_SOCK_RAW:
            *platformSocketType = SOCK_RAW;
            return true;

        case PAL_SOCK_RDM:
            *platformSocketType = SOCK_RDM;
            return true;

        case PAL_SOCK_SEQPACKET:
            *platformSocketType = SOCK_SEQPACKET;
            return true;
 
        default:
            *platformSocketType = static_cast<int>(palSocketType);
            return false;           
    }
}

static bool TryConvertProtocolTypePalToPlatform(int32_t palProtocolType, int* platformProtocolType)
{
    assert(platformProtocolType != nullptr);

    switch (palProtocolType)
    {
        case PAL_PT_TCP:
            *platformProtocolType = IPPROTO_TCP;
            return true;

        case PAL_PT_UDP:
            *platformProtocolType = IPPROTO_UDP;
            return true;

        default:
            *platformProtocolType = static_cast<int>(palProtocolType);
            return false;
    }
}

extern "C" Error Socket(int32_t addressFamily, int32_t socketType, int32_t protocolType, int32_t* createdSocket)
{
    if (createdSocket == nullptr)
    {
        return PAL_EFAULT;
    }

    // NOTE: we do not check for success on any of these calls b/c this API is deliberately
    //       transparent w.r.t. unmapped values. This allows the use of platform-specific
    //       address families and protocol types at the expense of potentially confusing
    //       behavior when PAL and platform values overlap.
    sa_family_t platformAddressFamily;
    int platformSocketType, platformProtocolType;

    TryConvertAddressFamilyPalToPlatform(addressFamily, &platformAddressFamily);
    TryConvertSocketTypePalToPlatform(socketType, &platformSocketType);
    TryConvertProtocolTypePalToPlatform(protocolType, &platformProtocolType);

    *createdSocket = socket(platformAddressFamily, platformSocketType, platformProtocolType);
    return *createdSocket != -1 ? PAL_SUCCESS : ConvertErrorPlatformToPal(errno);
}

static void ConvertFdSetPlatformToPal(FdSet& palSet, fd_set& platformSet, int32_t fdCount)
{
    assert(fdCount >= 0);

#if !HAVE_FDS_BITS && !HAVE_PRIVATE_FDS_BITS
    for (int i = 0; i < fdCount; i++)
    {
        int word = i / static_cast<int>(PAL_FDSET_NFD_BITS);
        int bit = i % static_cast<int>(PAL_FDSET_NFD_BITS);
        if ((palSet.Bits[word] & (1 << bit)) == 0)
        {
            FD_SET(i, &platformSet);
        }
        else
        {
            FD_CLR(i, &platformSet);
        }
    }
#else

    size_t bytesToCopy = static_cast<size_t>((fdCount / 8) + ((fdCount % 8) == 0 ? 1 : 0));

    uint8_t* dest;
#if HAVE_FDS_BITS
    dest = reinterpret_cast<uint8_t*>(&platformSet.fds_bits[0]);
#elif HAVE_PRIVATE_FDS_BITS
    dest = reinterpret_cast<uint8_t*>(&platformSet.__fds_bits[0]);
#endif

    memcpy(dest, &palSet.Bits[0], bytesToCopy);
#endif
}

static void ConvertFdSetPalToPlatform(fd_set& platformSet, FdSet& palSet, int32_t fdCount)
{
    assert(fdCount >= 0);

#if !HAVE_FDS_BITS && !HAVE_PRIVATE_FDS_BITS
    for (int i = 0; i < fdCount; i++)
    {
        uint32_t* word = &palSet.Bits[i / static_cast<int>(PAL_FDSET_NFD_BITS)];
        uint32_t mask = 1 << (i % static_cast<int>(PAL_FDSET_NFD_BITS));

        if (FD_ISSET(i, &platformSet))
        {
            *word |= mask;
        }
        else
        {
            *word &= ~mask;
        }
    }
#else
    size_t bytesToCopy = static_cast<size_t>((fdCount / 8) + ((fdCount % 8) == 0 ? 1 : 0));

    uint8_t* source;
#if HAVE_FDS_BITS
    source = reinterpret_cast<uint8_t*>(&platformSet.fds_bits[0]);
#elif HAVE_PRIVATE_FDS_BITS
    source = reinterpret_cast<uint8_t*>(&platformSet.__fds_bits[0]);
#endif

    memcpy(&palSet.Bits[0], source, bytesToCopy);
#endif
}

extern "C" Error Select(int32_t fdCount, FdSet* readFdSet, FdSet* writeFdSet, FdSet* errorFdSet, int32_t microseconds, int32_t* selected)
{
    if (selected == nullptr)
    {
        return PAL_EFAULT;
    }

    if (fdCount < 0 || fdCount > PAL_FDSET_MAX_FDS || microseconds < -1)
    {
        return PAL_EINVAL;
    }

    fd_set* readFds = nullptr;
    fd_set* writeFds = nullptr;
    fd_set* errorFds = nullptr;
    timeval* timeout = nullptr;
    timeval tv;

    if (readFdSet != nullptr)
    {
        readFds = reinterpret_cast<fd_set*>(alloca(sizeof(fd_set)));
        ConvertFdSetPalToPlatform(*readFds, *readFdSet, fdCount);
    }

    if (writeFdSet != nullptr)
    {
        writeFds = reinterpret_cast<fd_set*>(alloca(sizeof(fd_set)));
        ConvertFdSetPalToPlatform(*writeFds, *writeFdSet, fdCount);
    }

    if (errorFdSet != nullptr)
    {
        errorFds = reinterpret_cast<fd_set*>(alloca(sizeof(fd_set)));
        ConvertFdSetPalToPlatform(*errorFds, *errorFdSet, fdCount);
    }

    if (microseconds != -1)
    {
        tv.tv_sec = microseconds / 1000000;
        tv.tv_usec = microseconds % 1000000;
        timeout = &tv;
    }

    int rv = select(fdCount, readFds, writeFds, errorFds, timeout);
    if (rv == -1)
    {
        return ConvertErrorPlatformToPal(errno);
    }

    if (readFdSet != nullptr)
    {
        ConvertFdSetPlatformToPal(*writeFdSet, *writeFds, fdCount);
    }

    if (writeFdSet != nullptr)
    {
        ConvertFdSetPlatformToPal(*writeFdSet, *writeFds, fdCount);
    }

    if (errorFdSet != nullptr)
    {
        ConvertFdSetPlatformToPal(*errorFdSet, *errorFds, fdCount);
    }

    *selected = rv;
    return PAL_SUCCESS;
}

extern "C" Error GetBytesAvailable(int32_t socket, int32_t* available)
{
    if (available == nullptr)
    {
        return PAL_EFAULT;
    }

    int avail;
    int err = ioctl(socket, FIONREAD, &avail);
    if (err == -1)
    {
        return ConvertErrorPlatformToPal(errno);
    }

    *available = static_cast<int32_t>(avail);
    return PAL_SUCCESS;
}
