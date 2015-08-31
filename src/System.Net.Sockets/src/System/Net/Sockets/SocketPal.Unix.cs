// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Threading.Tasks;

namespace System.Net.Sockets
{
    internal static class SocketPal
    {
        public static SocketError GetLastSocketError()
        {
            return GetSocketErrorForErrorCode(Interop.Sys.GetLastError());
        }

        public static SocketError GetSocketErrorForErrorCode(Interop.Error errorCode)
        {
            // TODO: audit these using winsock.h
            switch (errorCode)
            {
                case (Interop.Error)0:
                    return SocketError.Success;

                case Interop.Error.EINTR:
                    return SocketError.Interrupted;

                case Interop.Error.EACCES:
                    return SocketError.AccessDenied;

                case Interop.Error.EFAULT:
                    return SocketError.Fault;

                case Interop.Error.EINVAL:
                    return SocketError.InvalidArgument;

                case Interop.Error.EMFILE:
                case Interop.Error.ENFILE:
                    return SocketError.TooManyOpenSockets;

                case Interop.Error.EAGAIN:
                    return SocketError.WouldBlock;

                case Interop.Error.EINPROGRESS:
                    return SocketError.InProgress;

                case Interop.Error.EALREADY:
                    return SocketError.AlreadyInProgress;

                case Interop.Error.ENOTSOCK:
                    return SocketError.NotSocket;

                case Interop.Error.EDESTADDRREQ:
                    return SocketError.DestinationAddressRequired;

                case Interop.Error.EMSGSIZE:
                    return SocketError.MessageSize;

                case Interop.Error.EPROTOTYPE:
                    return SocketError.ProtocolType;

                case Interop.Error.ENOPROTOOPT:
                    return SocketError.ProtocolOption;

                case Interop.Error.EPROTONOSUPPORT:
                    return SocketError.ProtocolNotSupported;

                // SocketError.SocketNotSupported
                // SocketError.OperationNotSupported
                // SocketError.ProtocolFamilyNotSupported

                case Interop.Error.EAFNOSUPPORT:
                    return SocketError.AddressFamilyNotSupported;

                case Interop.Error.EADDRINUSE:
                    return SocketError.AddressAlreadyInUse;

                case Interop.Error.EADDRNOTAVAIL:
                    return SocketError.AddressNotAvailable;

                case Interop.Error.ENETDOWN:
                    return SocketError.NetworkDown;

                case Interop.Error.ENETUNREACH:
                    return SocketError.NetworkUnreachable;

                case Interop.Error.ENETRESET:
                    return SocketError.NetworkReset;

                case Interop.Error.ECONNABORTED:
                    return SocketError.ConnectionAborted;

                case Interop.Error.ECONNRESET:
                    return SocketError.ConnectionReset;

                // SocketError.NoBufferSpaceAvailable

                case Interop.Error.EISCONN:
                    return SocketError.IsConnected;

                case Interop.Error.ENOTCONN:
                    return SocketError.NotConnected;

                // SocketError.Shutdown

                case Interop.Error.ETIMEDOUT:
                    return SocketError.TimedOut;

                case Interop.Error.ECONNREFUSED:
                    return SocketError.ConnectionRefused;

                // SocketError.HostDown

                case Interop.Error.EHOSTUNREACH:
                    return SocketError.HostUnreachable;

                // SocketError.ProcessLimit

                // Extended Windows Sockets error constant definitions
                // SocketError.SystemNotReady
                // SocketError.VersionNotSupported
                // SocketError.NotInitialized
                // SocketError.Disconnecting
                // SocketError.TypeNotFound
                // SocketError.HostNotFound
                // SocketError.TryAgain
                // SocketError.NoRecovery
                // SocketError.NoData

                // OS dependent errors
                // SocketError.IOPending
                // SocketError.OperationAborted

                default:
                    return SocketError.SocketError;
            }
        }

        public static int GetPlatformAddressFamily(AddressFamily addressFamily)
        {
            switch (addressFamily)
            {
                case AddressFamily.Unspecified:
                    return Interop.libc.AF_UNSPEC;

                case AddressFamily.Unix:
                    return Interop.libc.AF_UNIX;

                case AddressFamily.InterNetwork:
                    return Interop.libc.AF_INET;

                case AddressFamily.InterNetworkV6:
                    return Interop.libc.AF_INET6;

                default:
                    return (int)addressFamily;
            }
        }

        public static int GetPlatformSocketType(SocketType socketType)
        {
            switch (socketType)
            {
                case SocketType.Stream:
                    return Interop.libc.SOCK_STREAM;

                case SocketType.Dgram:
                    return Interop.libc.SOCK_DGRAM;

                case SocketType.Raw:
                    return Interop.libc.SOCK_RAW;

                case SocketType.Rdm:
                    return Interop.libc.SOCK_RDM;

                case SocketType.Seqpacket:
                    return Interop.libc.SOCK_SEQPACKET;

                default:
                    return (int)socketType;
            }
        }

        private static int GetPlatformSocketFlags(SocketFlags socketFlags)
        {
            const SocketFlags StandardFlagsMask = 
                SocketFlags.ControlDataTruncated |
                SocketFlags.DontRoute |
                SocketFlags.OutOfBand |
                SocketFlags.Peek |
                SocketFlags.Truncated;

            if ((int)(socketFlags & StandardFlagsMask) != 0)
            {
                // TODO: how to handle this?
                return (int)socketFlags;
            }

            return
                ((socketFlags & SocketFlags.ControlDataTruncated) == 0 ? 0 : Interop.libc.MSG_CTRUNC) |
                ((socketFlags & SocketFlags.DontRoute) == 0 ? 0 : Interop.libc.MSG_DONTROUTE) |
                ((socketFlags & SocketFlags.OutOfBand) == 0 ? 0 : Interop.libc.MSG_OOB) |
                ((socketFlags & SocketFlags.Peek) == 0 ? 0 : Interop.libc.MSG_PEEK) |
                ((socketFlags & SocketFlags.Truncated) == 0 ? 0 : Interop.libc.MSG_TRUNC);
        }

        private static bool GetPlatformOptionInfo(SocketOptionLevel optionLevel, SocketOptionName optionName, out int optLevel, out int optName)
        {
            // TODO: determine what option level honors these option names
            // - SocketOptionName.BsdUrgent
            // - case SocketOptionName.Expedited

            // TODO: decide how to handle option names that have no corresponding name on *nix
            switch (optionLevel)
            {
                case SocketOptionLevel.Socket:
                    optLevel = Interop.libc.SOL_SOCKET;
                    switch (optionName)
                    {
                        case SocketOptionName.Debug:
                            optName = Interop.libc.SO_DEBUG;
                            break;

                        case SocketOptionName.AcceptConnection:
                            optName = Interop.libc.SO_ACCEPTCONN;
                            break;

                        case SocketOptionName.ReuseAddress:
                            optName = Interop.libc.SO_REUSEADDR;
                            break;

                        case SocketOptionName.KeepAlive:
                            optName = Interop.libc.SO_KEEPALIVE;
                            break;

                        case SocketOptionName.DontRoute:
                            optName = Interop.libc.SO_DONTROUTE;
                            break;

                        case SocketOptionName.Broadcast:
                            optName = Interop.libc.SO_BROADCAST;
                            break;

                        // SocketOptionName.UseLoopback:

                        case SocketOptionName.Linger:
                            optName = Interop.libc.SO_LINGER;
                            break;

                        case SocketOptionName.OutOfBandInline:
                            optName = Interop.libc.SO_OOBINLINE;
                            break;

                        // case SocketOptionName.DontLinger
                        // case SocketOptionName.ExclusiveAddressUse

                        case SocketOptionName.SendBuffer:
                            optName = Interop.libc.SO_SNDBUF;
                            break;

                        case SocketOptionName.ReceiveBuffer:
                            optName = Interop.libc.SO_RCVBUF;
                            break;

                        case SocketOptionName.SendLowWater:
                            optName = Interop.libc.SO_SNDLOWAT;
                            break;

                        case SocketOptionName.ReceiveLowWater:
                            optName = Interop.libc.SO_RCVLOWAT;
                            break;

                        case SocketOptionName.SendTimeout:
                            optName = Interop.libc.SO_SNDTIMEO;
                            break;

                        case SocketOptionName.ReceiveTimeout:
                            optName = Interop.libc.SO_RCVTIMEO;
                            break;

                        case SocketOptionName.Error:
                            optName = Interop.libc.SO_ERROR;
                            break;

                        case SocketOptionName.Type:
                            optName = Interop.libc.SO_TYPE;
                            break;

                        // case SocketOptionName.MaxConnections
                        // case SocketOptionName.UpdateAcceptContext:
                        // case SocketOptionName.UpdateConnectContext:

                        default:
                            optName = (int)optionName;
                            return false;
                    }
                    return true;

                case SocketOptionLevel.Tcp:
                    optLevel = Interop.libc.IPPROTO_TCP;
                    switch (optionName)
                    {
                        case SocketOptionName.NoDelay:
                            optName = Interop.libc.TCP_NODELAY;
                            break;

                        default:
                            optName = (int)optionName;
                            return false;
                    }
                    return true;

                case SocketOptionLevel.Udp:
                    optLevel = Interop.libc.IPPROTO_UDP;

                    // case SocketOptionName.NoChecksum:
                    // case SocketOptionName.ChecksumCoverage:

                    optName = (int)optionName;
                    return false;

                case SocketOptionLevel.IP:
                    optLevel = Interop.libc.IPPROTO_IP;
                    switch (optionName)
                    {
                        case SocketOptionName.IPOptions:
                            optName = Interop.libc.IP_OPTIONS;
                            break;

                        case SocketOptionName.HeaderIncluded:
                            optName = Interop.libc.IP_HDRINCL;
                            break;

                        case SocketOptionName.TypeOfService:
                            optName = Interop.libc.IP_TOS;
                            break;

                        case SocketOptionName.IpTimeToLive:
                            optName = Interop.libc.IP_TTL;
                            break;

                        case SocketOptionName.MulticastInterface:
                            optName = Interop.libc.IP_MULTICAST_IF;
                            break;

                        case SocketOptionName.MulticastTimeToLive:
                            optName = Interop.libc.IP_MULTICAST_TTL;
                            break;

                        case SocketOptionName.MulticastLoopback:
                            optName = Interop.libc.IP_MULTICAST_LOOP;
                            break;

                        case SocketOptionName.AddMembership:
                            optName = Interop.libc.IP_ADD_MEMBERSHIP;
                            break;

                        case SocketOptionName.DropMembership:
                            optName = Interop.libc.IP_DROP_MEMBERSHIP;
                            break;

                        // case SocketOptionName.DontFragment

                        case SocketOptionName.AddSourceMembership:
                            optName = Interop.libc.IP_ADD_SOURCE_MEMBERSHIP;
                            break;

                        case SocketOptionName.DropSourceMembership:
                            optName = Interop.libc.IP_DROP_SOURCE_MEMBERSHIP;
                            break;

                        case SocketOptionName.BlockSource:
                            optName = Interop.libc.IP_BLOCK_SOURCE;
                            break;

                        case SocketOptionName.UnblockSource:
                            optName = Interop.libc.IP_UNBLOCK_SOURCE;
                            break;

                        case SocketOptionName.PacketInformation:
                            optName = Interop.libc.IP_PKTINFO;
                            break;

                        default:
                            optName = (int)optionName;
                            return false;
                    }
                    return true;

                case SocketOptionLevel.IPv6:
                    optLevel = Interop.libc.IPPROTO_IPV6;
                    switch (optionName)
                    {
                        // case SocketOptionName.HopLimit:

                        // case SocketOption.IPProtectionLevel:

                        case SocketOptionName.IPv6Only:
                            optName = Interop.libc.IPV6_V6ONLY;
                            break;

                        default:
                            optName = (int)optionName;
                            return false;
                    }
                    return true;

                default:
                    // TODO: rethink this
                    optLevel = (int)optionLevel;
                    optName = (int)optionName;
                    return false;
            }
        }

        public static int GetPlatformSocketShutdown(SocketShutdown how)
        {
            switch (how)
            {
                case SocketShutdown.Receive:
                    return Interop.libc.SHUT_RD;

                case SocketShutdown.Send:
                    return Interop.libc.SHUT_WR;

                case SocketShutdown.Both:
                    return Interop.libc.SHUT_RDWR;

                default:
                    // TODO: rethink this
                    return (int)how;
            }
        }

        public static SafeCloseSocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
        {
            SafeCloseSocket handle = SafeCloseSocket.CreateSocket(addressFamily, socketType, protocolType);
            if (handle.IsInvalid)
            {
                // TODO: fix the exception here
                throw new SocketException((int)GetLastSocketError());
            }
            return handle;
        }

        public static unsafe SafeCloseSocket CreateSocket(SocketInformation socketInformation, out AddressFamily addressFamily, out SocketType socketType, out ProtocolType protocolType)
        {
            throw new PlatformNotSupportedException();
        }

        public static SocketError SetBlocking(SafeCloseSocket handle, bool shouldBlock, out bool willBlock)
        {
            int err = Interop.Sys.Fcntl.SetIsNonBlocking(handle.FileDescriptor, shouldBlock ? 0 : 1);
            if (err == -1)
            {
                // TODO: consider this value
                willBlock = shouldBlock;
                return GetLastSocketError();
            }

            willBlock = shouldBlock;
            return SocketError.Success;
        }

        public static unsafe SocketError GetSockName(SafeCloseSocket handle, byte[] buffer, ref int nameLen)
        {
            int err;
            uint addrLen = (uint)nameLen;
            fixed (byte* rawBuffer = buffer)
            {
                err = Interop.libc.getsockname(handle.FileDescriptor, (Interop.libc.sockaddr*)rawBuffer, &addrLen);
            }
            nameLen = (int)addrLen;

            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static unsafe SocketError GetAvailable(SafeCloseSocket handle, out int available)
        {
            int value = 0;
            int err = Interop.libc.ioctl(handle.FileDescriptor, (UIntPtr)Interop.libc.FIONREAD, &value);
            available = value;

            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static unsafe SocketError GetPeerName(SafeCloseSocket handle, byte[] buffer, ref int nameLen)
        {
            int err;
            uint addrLen = (uint)nameLen;
            fixed (byte* rawBuffer = buffer)
            {
                err = Interop.libc.getpeername(handle.FileDescriptor, (Interop.libc.sockaddr*)rawBuffer, &addrLen);
            }
            nameLen = (int)addrLen;

            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static unsafe SocketError Bind(SafeCloseSocket handle, byte[] buffer, int nameLen)
        {
            int err;
            fixed (byte* rawBuffer = buffer)
            {
                err = Interop.libc.bind(handle.FileDescriptor, (Interop.libc.sockaddr*)rawBuffer, (uint)nameLen);
            }

            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static SocketError Listen(SafeCloseSocket handle, int backlog)
        {
            int err = Interop.libc.listen(handle.FileDescriptor, backlog);

            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static SafeCloseSocket Accept(SafeCloseSocket handle, byte[] buffer, ref int nameLen)
        {
            return SafeCloseSocket.Accept(handle, buffer, ref nameLen);
        }

        public static unsafe SocketError Connect(SafeCloseSocket handle, byte[] peerAddress, int peerAddressLen)
        {
            int err;
            fixed (byte* rawPeerAddress = peerAddress)
            {
                var peerSockAddr = (Interop.libc.sockaddr*)rawPeerAddress;
                err = Interop.libc.connect(handle.FileDescriptor, peerSockAddr, (uint)peerAddressLen);
            }

            if (err != -1)
            {
                return SocketError.Success;
            }

            // Unix returns EINPROGRESS instead of EWOULDBLOCK for non-blocking connect operations
            SocketError errorCode = GetLastSocketError();
            return errorCode == SocketError.InProgress ? SocketError.WouldBlock : errorCode;
        }

        public static unsafe SocketError Send(SafeCloseSocket handle, BufferOffsetSize[] buffers, SocketFlags socketFlags, out int bytesTransferred)
        {
            var iovecs = new Interop.libc.iovec[buffers.Length];
            var handles = new GCHandle[buffers.Length];

            try
            {
                for (int i = 0; i < buffers.Length; i++)
                {
                    handles[i] = GCHandle.Alloc(buffers[i].Buffer, GCHandleType.Pinned);
                    iovecs[i].iov_base = &((byte*)handles[i].AddrOfPinnedObject())[buffers[i].Offset];
                    iovecs[i].iov_len = (IntPtr)buffers[i].Size;
                }

                int sent;
                fixed (Interop.libc.iovec* iov = iovecs)
                {
                    var msghdr = new Interop.libc.msghdr {
                        msg_name = null,
                        msg_namelen = 0,
                        msg_iov = iov,
                        msg_iovlen = (IntPtr)iovecs.Length,
                        msg_control = null,
                        msg_controllen = IntPtr.Zero,
                    };

                    sent = (int)Interop.libc.sendmsg(handle.FileDescriptor, &msghdr, GetPlatformSocketFlags(socketFlags));
                }

                if (sent == -1)
                {
                    bytesTransferred = 0;
                    return GetLastSocketError();
                }

                bytesTransferred = sent;
                return SocketError.Success;
            }
            finally
            {
                for (int i = 0; i < handles.Length; i++)
                {
                    if (handles[i].IsAllocated)
                    {
                        handles[i].Free();
                    }
                }
            }
        }

        public static unsafe SocketError Send(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, out int bytesTransferred)
        {
            var iovecs = new Interop.libc.iovec[buffers.Count];
            var handles = new GCHandle[buffers.Count];

            try
            {
                for (int i = 0; i < buffers.Count; i++)
                {
                    handles[i] = GCHandle.Alloc(buffers[i].Array, GCHandleType.Pinned);
                    iovecs[i].iov_base = &((byte*)handles[i].AddrOfPinnedObject())[buffers[i].Offset];
                    iovecs[i].iov_len = (IntPtr)buffers[i].Count;
                }

                int sent;
                fixed (Interop.libc.iovec* iov = iovecs)
                {
                    var msghdr = new Interop.libc.msghdr {
                        msg_name = null,
                        msg_namelen = 0,
                        msg_iov = iov,
                        msg_iovlen = (IntPtr)iovecs.Length,
                        msg_control = null,
                        msg_controllen = IntPtr.Zero,
                    };

                    sent = (int)Interop.libc.sendmsg(handle.FileDescriptor, &msghdr, GetPlatformSocketFlags(socketFlags));
                }

                if (sent == -1)
                {
                    bytesTransferred = 0;
                    return GetLastSocketError();
                }

                bytesTransferred = sent;
                return SocketError.Success;
            }
            finally
            {
                for (int i = 0; i < handles.Length; i++)
                {
                    if (handles[i].IsAllocated)
                    {
                        handles[i].Free();
                    }
                }
            }
        }

        // TODO: refactor to accommodate GetLastSocketError
        public static unsafe int Send(SafeCloseSocket handle, byte[] buffer, int offset, int size, SocketFlags socketFlags)
        {
            int sent;
            if (buffer.Length == 0)
            {
                sent = (int)Interop.libc.send(handle.FileDescriptor, null, IntPtr.Zero, GetPlatformSocketFlags(socketFlags));
            }
            else
            {
                fixed (byte* pinnedBuffer = buffer)
                {
                    sent = (int)Interop.libc.send(handle.FileDescriptor, &pinnedBuffer[offset], (IntPtr)size, GetPlatformSocketFlags(socketFlags));
                }
            }

            return sent;
        }

        // TODO: refactor to accommodate GetLastSocketError
        public static unsafe int SendTo(SafeCloseSocket handle, byte[] buffer, int offset, int size, SocketFlags socketFlags, byte[] peerAddress, int peerAddressSize)
        {
            int sent;
            fixed (byte* rawPeerAddress = peerAddress)
            {
                Interop.libc.sockaddr* peerSockAddr = (Interop.libc.sockaddr*)rawPeerAddress;
                if (buffer.Length == 0)
                {
                    sent = (int)Interop.libc.sendto(handle.FileDescriptor, null, IntPtr.Zero, GetPlatformSocketFlags(socketFlags), peerSockAddr, (uint)peerAddressSize);
                }
                else
                {
                    fixed (byte* pinnedBuffer = buffer)
                    {
                        sent = (int)Interop.libc.sendto(handle.FileDescriptor, &pinnedBuffer[offset], (IntPtr)size, GetPlatformSocketFlags(socketFlags), peerSockAddr, (uint)peerAddressSize);
                    }
                }
            }

            return sent;
        }

        public static unsafe SocketError Receive(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, ref SocketFlags socketFlags, out int bytesTransferred)
        {
            var iovecs = new Interop.libc.iovec[buffers.Count];
            var handles = new GCHandle[buffers.Count];

            try
            {
                for (int i = 0; i < buffers.Count; i++)
                {
                    handles[i] = GCHandle.Alloc(buffers[i].Array, GCHandleType.Pinned);
                    iovecs[i].iov_base = &((byte*)handles[i].AddrOfPinnedObject())[buffers[i].Offset];
                    iovecs[i].iov_len = (IntPtr)buffers[i].Count;
                }

                int received;
                fixed (Interop.libc.iovec* iov = iovecs)
                {
                    var msghdr = new Interop.libc.msghdr {
                        msg_name = null,
                        msg_namelen = 0,
                        msg_iov = iov,
                        msg_iovlen = (IntPtr)iovecs.Length,
                        msg_control = null,
                        msg_controllen = IntPtr.Zero,
                    };

                    received = (int)Interop.libc.recvmsg(handle.FileDescriptor, &msghdr, GetPlatformSocketFlags(socketFlags));
                }

                if (received == -1)
                {
                    bytesTransferred = 0;
                    return GetLastSocketError();
                }

                bytesTransferred = received;
                return SocketError.Success;
            }
            finally
            {
                for (int i = 0; i < handles.Length; i++)
                {
                    if (handles[i].IsAllocated)
                    {
                        handles[i].Free();
                    }
                }
            }
        }

        // TODO: refactor to accommodate GetLastSocketError
        public static unsafe int Receive(SafeCloseSocket handle, byte[] buffer, int offset, int size, SocketFlags socketFlags)
        {
            int received;
            if (buffer.Length == 0)
            {
                received = (int)Interop.libc.recv(handle.FileDescriptor, null, IntPtr.Zero, GetPlatformSocketFlags(socketFlags));
            }
            else
            {
                fixed (byte* pinnedBuffer = buffer)
                {
                    received = (int)Interop.libc.recv(handle.FileDescriptor, &pinnedBuffer[offset], (IntPtr)size, GetPlatformSocketFlags(socketFlags));
                }
            }

            return received;
        }

        public static unsafe SocketError ReceiveMessageFrom(Socket socket, SafeCloseSocket handle, byte[] buffer, int offset, int size, ref SocketFlags socketFlags, Internals.SocketAddress socketAddress, out Internals.SocketAddress receiveAddress, out IPPacketInformation ipPacketInformation, out int bytesTransferred)
        {
            int received;
            fixed (byte* peerAddress = socketAddress.Buffer)
            fixed (byte* pinnedBuffer = buffer)
            {
                var iovec = new Interop.libc.iovec {
                    iov_base = &pinnedBuffer[offset],
                    iov_len = (IntPtr)size
                };

                var msghdr = new Interop.libc.msghdr {
                    msg_name = peerAddress,
                    msg_namelen = (uint)socketAddress.InternalSize,
                    msg_iov = &iovec,
                    msg_iovlen = (IntPtr)1,
                    msg_control = null,
                    msg_controllen = IntPtr.Zero,
                };

                received = (int)Interop.libc.recvmsg(handle.FileDescriptor, &msghdr, GetPlatformSocketFlags(socketFlags));
                socketAddress.InternalSize = (int)msghdr.msg_namelen; // TODO: is this OK?
            }

            // TODO: see if some reasonable value for networkInterface can be derived
            receiveAddress = socketAddress;
            ipPacketInformation = new IPPacketInformation(socketAddress.GetIPAddress(), -1);

            if (received == -1)
            {
                bytesTransferred = 0;
                return GetLastSocketError();
            }

            bytesTransferred = received;
            return SocketError.Success;
        }

        // TODO: refactor to accommodate GetLastSocketError
        public static unsafe int ReceiveFrom(SafeCloseSocket handle, byte[] buffer, int offset, int size, SocketFlags socketFlags, byte[] peerAddress, ref int addressLength)
        {
            int received;
            uint peerAddrLen = (uint)addressLength;
            fixed (byte* rawPeerAddress = peerAddress)
            {
                Interop.libc.sockaddr* peerSockAddr = (Interop.libc.sockaddr*)rawPeerAddress;
                if (buffer.Length == 0)
                {
                    received = (int)Interop.libc.recvfrom(handle.FileDescriptor, null, IntPtr.Zero, GetPlatformSocketFlags(socketFlags), peerSockAddr, &peerAddrLen);
                }
                else
                {
                    fixed (byte* pinnedBuffer = buffer)
                    {
                        received = (int)Interop.libc.recvfrom(handle.FileDescriptor, &pinnedBuffer[offset], (IntPtr)size, GetPlatformSocketFlags(socketFlags), peerSockAddr, &peerAddrLen);
                    }
                }
            }

            addressLength = (int)peerAddrLen;
            return received;
        }

        public static SocketError Ioctl(SafeCloseSocket handle, int ioControlCode, byte[] optionInValue, byte[] optionOutValue, out int optionLength)
        {
            // TODO: can this be supported in some reasonable fashion?
            throw new PlatformNotSupportedException();
        }

        public static SocketError IoctlInternal(SafeCloseSocket handle, IOControlCode ioControlCode, IntPtr optionInValue, int inValueLength, IntPtr optionOutValue, int outValueLength, out int optionLength)
        {
            // TODO: can this be supported in some reasonable fashion?
            throw new PlatformNotSupportedException();
        }

        public static unsafe SocketError SetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, int optionValue)
        {
            int optLevel, optName;
            GetPlatformOptionInfo(optionLevel, optionName, out optLevel, out optName);

            int err = Interop.libc.setsockopt(handle.FileDescriptor, optLevel, optName, &optionValue, sizeof(int));

            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static unsafe SocketError SetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue)
        {
            int optLevel, optName;
            GetPlatformOptionInfo(optionLevel, optionName, out optLevel, out optName);

            int err;
            if (optionValue == null || optionValue.Length == 0)
            {
                err = Interop.libc.setsockopt(handle.FileDescriptor, optLevel, optName, null, 0);
            }
            else
            {
                fixed (byte* pinnedValue = optionValue)
                {
                    err = Interop.libc.setsockopt(handle.FileDescriptor, optLevel, optName, pinnedValue, (uint)optionValue.Length);
                }
            }

            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static unsafe SocketError GetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, out int optionValue)
        {
            int optLevel, optName;
            GetPlatformOptionInfo(optionLevel, optionName, out optLevel, out optName);

            uint optLen = 4; // sizeof(int)
            int value = 0;

            int err = Interop.libc.getsockopt(handle.FileDescriptor, optLevel, optName, &value, &optLen);

            optionValue = value;
            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static unsafe SocketError GetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue, ref int optionLength)
        {
            int optLevel, optName;
            GetPlatformOptionInfo(optionLevel, optionName, out optLevel, out optName);

            uint optLen = (uint)optionLength;

            int err;
            if (optionValue == null || optionValue.Length == 0)
            {
                optLen = 0;
                err = Interop.libc.getsockopt(handle.FileDescriptor, optLevel, optName, null, &optLen);
            }
            else
            {
                fixed (byte* pinnedValue = optionValue)
                {
                    err = Interop.libc.getsockopt(handle.FileDescriptor, optLevel, optName, pinnedValue, &optLen);
                }
            }

            optionLength = (int)optLen;
            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static unsafe SocketError Poll(SafeCloseSocket handle, int microseconds, SelectMode mode, out bool status)
        {
            var fdset = new Interop.libc.fd_set();
            fdset.Set(handle.FileDescriptor);

            // TODO: this should probably be 0 if readfds, writefds, and errorfds are all null
            int nfds = handle.FileDescriptor + 1;
            Interop.libc.fd_set* readfds = mode == SelectMode.SelectRead ? &fdset : null;
            Interop.libc.fd_set* writefds = mode == SelectMode.SelectWrite ? &fdset : null;
            Interop.libc.fd_set* errorfds = mode == SelectMode.SelectError ? &fdset : null;

            int socketCount = 0;
            if (microseconds != -1)
            {
                var tv = new Interop.libc.timeval(microseconds);
                socketCount = Interop.libc.select(nfds, readfds, writefds, errorfds, &tv);
            }
            else
            {
                socketCount = Interop.libc.select(nfds, readfds, writefds, errorfds, null);
            }

            if (socketCount == -1)
            {
                status = false;
                return SocketError.SocketError; // TODO: should this be SCH.GetLastSocketError()?
            }

            status = fdset.IsSet(handle.FileDescriptor);
            return (SocketError)socketCount;
        }

        public static unsafe SocketError Select(IList checkRead, IList checkWrite, IList checkError, int microseconds)
        {
            var readSet = new Interop.libc.fd_set();
            int maxReadFd = Socket.FillFdSetFromSocketList(ref readSet, checkRead);

            var writeSet = new Interop.libc.fd_set();
            int maxWriteFd = Socket.FillFdSetFromSocketList(ref writeSet, checkWrite);

            var errorSet = new Interop.libc.fd_set();
            int maxErrorFd = Socket.FillFdSetFromSocketList(ref errorSet, checkError);

            int nfds = 0;
            Interop.libc.fd_set* readfds = null;
            Interop.libc.fd_set* writefds = null;
            Interop.libc.fd_set* errorfds = null;

            if (maxReadFd != 0)
            {
                readfds = &readSet;
                nfds = maxReadFd;
            }

            if (maxWriteFd != 0)
            {
                writefds = &writeSet;
                if (maxWriteFd > nfds)
                {
                    nfds = maxWriteFd;
                }
            }

            if (maxErrorFd != 0)
            {
                errorfds = &errorSet;
                if (maxErrorFd > nfds)
                {
                    nfds = maxErrorFd;
                }
            }

            int socketCount;
            if (microseconds != -1)
            {
                var tv = new Interop.libc.timeval(microseconds);
                socketCount = Interop.libc.select(nfds, readfds, writefds, errorfds, &tv);
            }
            else
            {
                socketCount = Interop.libc.select(nfds, readfds, writefds, errorfds, null);
            }

            GlobalLog.Print("Socket::Select() Interop.libc.select returns socketCount:" + socketCount);

            if (socketCount == -1)
            {
                return SocketError.SocketError; // TODO: should this be SCH.GetLastSocketError()?
            }

            Socket.FilterSocketListUsingFdSet(ref readSet, checkRead);
            Socket.FilterSocketListUsingFdSet(ref writeSet, checkWrite);
            Socket.FilterSocketListUsingFdSet(ref errorSet, checkError);

            return (SocketError)socketCount;
        }

        public static SocketError Shutdown(SafeCloseSocket handle, SocketShutdown how)
        {
            int err = Interop.libc.shutdown(handle.FileDescriptor, GetPlatformSocketShutdown(how));
            return err == -1 ? GetLastSocketError() : SocketError.Success;
        }

        public static unsafe SocketError ConnectAsync(Socket socket, SafeCloseSocket handle, byte[] socketAddress, int socketAddressLen, ConnectOverlappedAsyncResult asyncResult)
        {
            // TODO: audit "completed synchronously" behavior
            if (!handle.AsyncContext.ConnectAsync(socketAddress, socketAddressLen, asyncResult.CompletionCallback))
            {
                return (SocketError)asyncResult.ErrorCode;
            }

            return SocketError.IOPending;
        }

        public static unsafe SocketError SendAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // TODO: audit "completed synchronously" behavior
            if (!handle.AsyncContext.SendAsync(buffer, offset, count, GetPlatformSocketFlags(socketFlags), asyncResult.CompletionCallback))
            {
                return (SocketError)asyncResult.ErrorCode;
            }

            return SocketError.IOPending;
        }

        public static unsafe SocketError SendAsync(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // TODO: audit "completed synchronously" behavior
            if (!handle.AsyncContext.SendAsync(new BufferList(buffers), GetPlatformSocketFlags(socketFlags), asyncResult.CompletionCallback))
            {
                return (SocketError)asyncResult.ErrorCode;
            }

            return SocketError.IOPending;
        }

        public static unsafe SocketError SendAsync(SafeCloseSocket handle, BufferOffsetSize[] buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // TODO: audit "completed synchronously" behavior
            if (!handle.AsyncContext.SendAsync(new BufferList(buffers), GetPlatformSocketFlags(socketFlags), asyncResult.CompletionCallback))
            {
                return (SocketError)asyncResult.ErrorCode;
            }

            return SocketError.IOPending;
        }

        public static unsafe SocketError SendToAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, Internals.SocketAddress socketAddress, OverlappedAsyncResult asyncResult)
        {
            asyncResult.SocketAddress = socketAddress;

            // TODO: audit "completed synchronously" behavior
            if (!handle.AsyncContext.SendToAsync(buffer, offset, count, GetPlatformSocketFlags(socketFlags), socketAddress.Buffer, socketAddress.Size, asyncResult.CompletionCallback))
            {
                return (SocketError)asyncResult.ErrorCode;
            }

            return SocketError.IOPending;
        }

        public static unsafe SocketError ReceiveAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // TODO: audit "completed synchronously" behavior
            if (!handle.AsyncContext.ReceiveAsync(buffer, offset, count, GetPlatformSocketFlags(socketFlags), asyncResult.CompletionCallback))
            {
                return (SocketError)asyncResult.ErrorCode;
            }

            return SocketError.IOPending;
        }

        public static unsafe SocketError ReceiveAsync(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // TODO: audit "completed synchronously" behavior
            if (!handle.AsyncContext.ReceiveAsync(buffers, GetPlatformSocketFlags(socketFlags), asyncResult.CompletionCallback))
            {
                return (SocketError)asyncResult.ErrorCode;
            }

            return SocketError.IOPending;
        }

        public static unsafe SocketError ReceiveFromAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, Internals.SocketAddress socketAddress, OverlappedAsyncResult asyncResult)
        {
            asyncResult.SocketAddress = socketAddress;

            // TODO: audit "completed synchronously" behavior
            if (!handle.AsyncContext.ReceiveFromAsync(buffer, offset, count, GetPlatformSocketFlags(socketFlags), socketAddress.Buffer, socketAddress.InternalSize, asyncResult.CompletionCallback))
            {
                return (SocketError)asyncResult.ErrorCode;
            }

            return SocketError.IOPending;
        }

        public static unsafe SocketError AcceptAsync(Socket socket, SafeCloseSocket handle, SafeCloseSocket acceptHandle, int receiveSize, int socketAddressSize, AcceptOverlappedAsyncResult asyncResult)
        {
            Debug.Assert(acceptHandle == null);

            byte[] socketAddressBuffer = new byte[socketAddressSize];

            // TODO: audit "completed synchronously" behavior
            if (!handle.AsyncContext.AcceptAsync(socketAddressBuffer, socketAddressSize, asyncResult.CompletionCallback))
            {
                return (SocketError)asyncResult.ErrorCode;
            }

            return SocketError.IOPending;
        }
    }
}
