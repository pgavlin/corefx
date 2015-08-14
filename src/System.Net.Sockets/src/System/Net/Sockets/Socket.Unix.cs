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
    public partial class Socket
    {
        internal static class SocketPal
        {
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

            private static int GetPlatformOptionLevel(SocketOptionLevel optionLevel)
            {
                switch (optionLevel)
                {
                    case SocketOptionLevel.Socket:
                        return Interop.libc.SOL_SOCKET;

                    case SocketOptionLevel.Tcp:
                        return Interop.libc.IPPROTO_TCP;

                    case SocketOptionLevel.Udp:
                        return Interop.libc.IPPROTO_UDP;

                    case SocketOptionLevel.IP:
                        return Interop.libc.IPPROTO_IP;

                    case SocketOptionLevel.IPv6:
                        return Interop.libc.IPPROTO_IPV6;

                    default:
                        // TODO: rethink this
                        return (int)optionLevel;
                }
            }

            private static int GetPlatformOptionName(SocketOptionName optionName)
            {
                // TODO: some enum names have the same underlying value. This cannot be handled.
                switch (optionName)
                {
                    case SocketOptionName.Debug:
                        return Interop.libc.SO_DEBUG;

                    case SocketOptionName.AcceptConnection:
                        return Interop.libc.SO_ACCEPTCONN;

                    case SocketOptionName.ReuseAddress:
                        return Interop.libc.SO_REUSEADDR;

                    case SocketOptionName.KeepAlive:
                        return Interop.libc.SO_KEEPALIVE;

                    case SocketOptionName.DontRoute:
                        return Interop.libc.SO_DONTROUTE;

                    case SocketOptionName.Broadcast:
                        return Interop.libc.SO_BROADCAST;

                    // SocketOptionName.UseLoopback:

                    case SocketOptionName.Linger:
                        return Interop.libc.SO_LINGER;

                    case SocketOptionName.OutOfBandInline:
                        return Interop.libc.SO_OOBINLINE;

                    // case SocketOptionName.DontLinger
                    // case SocketOptionName.ExclusiveAddressUse

                    case SocketOptionName.SendBuffer:
                        return Interop.libc.SO_SNDBUF;

                    case SocketOptionName.ReceiveBuffer:
                        return Interop.libc.SO_RCVBUF;

                    case SocketOptionName.SendLowWater:
                        return Interop.libc.SO_SNDLOWAT;

                    case SocketOptionName.ReceiveLowWater:
                        return Interop.libc.SO_RCVLOWAT;

                    case SocketOptionName.SendTimeout:
                        return Interop.libc.SO_SNDTIMEO;

                    case SocketOptionName.ReceiveTimeout:
                        return Interop.libc.SO_RCVTIMEO;

                    case SocketOptionName.Error:
                        return Interop.libc.SO_ERROR;

                    case SocketOptionName.Type:
                        return Interop.libc.SO_TYPE;

                    // case SocketOptionName.MaxConnections

                    //case SocketOptionName.IPOptions:
                    //    return Interop.libc.IP_OPTIONS;

                    //case SocketOptionName.HeaderIncluded:
                    //    return Interop.libc.IP_HDRINCL;

                    case SocketOptionName.TypeOfService:
                        return Interop.libc.IP_TOS;

                    //case SocketOptionName.IpTimeToLive:
                    //    return Interop.libc.IP_TTL;

                    case SocketOptionName.MulticastInterface:
                        return Interop.libc.IP_MULTICAST_IF;

                    case SocketOptionName.MulticastTimeToLive:
                        return Interop.libc.IP_MULTICAST_TTL;

                    case SocketOptionName.MulticastLoopback:
                        return Interop.libc.IP_MULTICAST_LOOP;

                    case SocketOptionName.AddMembership:
                        return Interop.libc.IP_ADD_MEMBERSHIP;

                    case SocketOptionName.DropMembership:
                        return Interop.libc.IP_DROP_MEMBERSHIP;

                    // case SocketOptionName.DontFragment

                    case SocketOptionName.AddSourceMembership:
                        return Interop.libc.IP_ADD_SOURCE_MEMBERSHIP;

                    //case SocketOptionName.DropMembership:
                    //    return Interop.libc.IP_DROP_SOURCE_MEMBERSHIP;

                    case SocketOptionName.BlockSource:
                        return Interop.libc.IP_BLOCK_SOURCE;

                    case SocketOptionName.UnblockSource:
                        return Interop.libc.IP_UNBLOCK_SOURCE;

                    case SocketOptionName.PacketInformation:
                        return Interop.libc.IP_PKTINFO;

                    // case SocketOptionName.HopLimit:

                    // case SocketOption.IPProtectionLevel:

                    //case SocketOptionName.IPv6Only:
                    //    return Interop.libc.IPV6_V6ONLY;

                    //case SocketOptionName.NoDelay:
                    //    return Interop.libc.TCP_NODELAY;

                    // case SocketOptionName.BsdUrgent

                    // case SocketOptionName.Expedited

                    // case SocketOptionName.NoChecksum:

                    // case SocketOptionName.ChecksumCoverage:

                    // case SocketOptionName.UpdateAcceptContext:

                    // case SocketOptionName.UpdateConnectContext:

                    default:
                        // TODO: rethink this
                        return (int)optionName;
                }
            }

            private static int FillFdSetFromSocketList(ref Interop.libc.fd_set fdset, IList socketList)
            {
                if (socketList == null || socketList.Count == 0)
                {
                    return 0;
                }

                int maxFd = -1;
                for (int i = 0; i < socketList.Count; i++)
                {
                    var socket = socketList[i] as Socket;
                    if (socket == null)
                    {
                        throw new ArgumentException(SR.Format(SR.net_sockets_select, socketList[i].GetType().FullName, typeof(System.Net.Sockets.Socket).FullName), "socketList");
                    }

                    int fd = socket._handle.FileDescriptor;
                    fdset.Set(fd);

                    if (fd > maxFd)
                    {
                        maxFd = fd;
                    }
                }

                return maxFd + 1;
            }

            //
            // Transform the list socketList such that the only sockets left are those
            // with a file descriptor contained in the array "fileDescriptorArray"
            //
            private static void FilterSocketListUsingFdSet(ref Interop.libc.fd_set fdset, IList socketList)
            {
                if (socketList == null || socketList.Count == 0)
                {
                    return;
                }

                lock (socketList)
                {
                    for (int i = socketList.Count - 1; i >= 0; i--)
                    {
                        var socket = (Socket)socketList[i];
                        if (!fdset.IsSet(socket._handle.FileDescriptor))
                        {
                            socketList.RemoveAt(i);
                        }
                    }
                }
            }

            public static SafeCloseSocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
            {
                SafeCloseSocket handle = SafeCloseSocket.CreateSocket(addressFamily, socketType, protocolType);
                if (handle.IsInvalid)
                {
                    // TODO: fix the exception here
                    throw new SocketException((int)SafeCloseSocket.GetLastSocketError());
                }
                return handle;
            }

            public static unsafe SafeCloseSocket CreateSocket(SocketInformation socketInformation, out AddressFamily addressFamily, out SocketType socketType, out ProtocolType protocolType)
            {
                throw new PlatformNotSupportedException();
            }

            public static SocketError SetBlocking(SafeCloseSocket handle, bool shouldBlock, out bool willBlock)
            {
                int flags = Interop.libc.fcntl(handle.FileDescriptor, Interop.libc.FcntlCommands.F_GETFL);
                if (flags == -1)
                {
                    // TODO: consider this value
                    willBlock = shouldBlock;
                    return SafeCloseSocket.GetLastSocketError();
                }

                int newFlags = flags;
                if (shouldBlock)
                {
                    newFlags |= Interop.libc.O_NONBLOCK;
                }
                else
                {
                    newFlags &= ~Interop.libc.O_NONBLOCK;
                }

                if (flags == newFlags)
                {
                    willBlock = shouldBlock;
                    return SocketError.Success;
                }

                int err = Interop.libc.fcntl(handle.FileDescriptor, Interop.libc.FcntlCommands.F_SETFL, newFlags);
                if (err == -1)
                {
                    willBlock = (flags & Interop.libc.O_NONBLOCK) != 0;
                    return SafeCloseSocket.GetLastSocketError();
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

                return err == -1 ? SafeCloseSocket.GetLastSocketError() : SocketError.Success;
            }

            public static unsafe SocketError GetAvailable(SafeCloseSocket handle, out int available)
            {
                int value = 0;
                int err = Interop.libc.ioctl(handle.FileDescriptor, Interop.libc.FIONREAD, &value);
                available = value;

                return err == -1 ? SafeCloseSocket.GetLastSocketError() : SocketError.Success;
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

                return err == -1 ? SafeCloseSocket.GetLastSocketError() : SocketError.Success;
            }

            public static unsafe SocketError Bind(SafeCloseSocket handle, byte[] buffer, int nameLen)
            {
                int err;
                fixed (byte* rawBuffer = buffer)
                {
                    err = Interop.libc.bind(handle.FileDescriptor, (Interop.libc.sockaddr*)rawBuffer, (uint)nameLen);
                }

                return err == -1 ? SafeCloseSocket.GetLastSocketError() : SocketError.Success;
            }

            public static SocketError Listen(SafeCloseSocket handle, int backlog)
            {
                int err = Interop.libc.listen(handle.FileDescriptor, backlog);

                return err == -1 ? SafeCloseSocket.GetLastSocketError() : SocketError.Success;
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

                return err == -1 ? SafeCloseSocket.GetLastSocketError() : SocketError.Success;
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
                        return SafeCloseSocket.GetLastSocketError();
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
                        return SafeCloseSocket.GetLastSocketError();
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
                        return SafeCloseSocket.GetLastSocketError();
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

            public static unsafe SocketError ReceiveMessageFrom(Socket socket, byte[] buffer, int offset, int size, ref SocketFlags socketFlags, Internals.SocketAddress socketAddress, out Internals.SocketAddress receiveAddress, out IPPacketInformation ipPacketInformation, out int bytesTransferred)
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

                    received = (int)Interop.libc.recvmsg(socket._handle.FileDescriptor, &msghdr, GetPlatformSocketFlags(socketFlags));
                    socketAddress.InternalSize = (int)msghdr.msg_namelen; // TODO: is this OK?
                }

                // TODO: see if some reasonable value for networkInterface can be derived
                receiveAddress = socketAddress;
                ipPacketInformation = new IPPacketInformation(socketAddress.GetIPAddress(), -1);

                if (received == -1)
                {
                    bytesTransferred = 0;
                    return SafeCloseSocket.GetLastSocketError();
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

            public static unsafe SocketError SetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue)
            {
                int optLevel = GetPlatformOptionLevel(optionLevel);
                int optName = GetPlatformOptionName(optionName);

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

                return err == -1 ? SafeCloseSocket.GetLastSocketError() : SocketError.Success;
            }

            public static unsafe SocketError GetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, out int optionValue)
            {
                int optLevel = GetPlatformOptionLevel(optionLevel);
                int optName = GetPlatformOptionName(optionName);
                uint optLen = 4; // sizeof(int)
                int value = 0;

                int err = Interop.libc.getsockopt(handle.FileDescriptor, optLevel, optName, &value, &optLen);

                optionValue = value;
                return err == -1 ? SafeCloseSocket.GetLastSocketError() : SocketError.Success;
            }

            public static unsafe SocketError GetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue, ref int optionLength)
            {
                int optLevel = GetPlatformOptionLevel(optionLevel);
                int optName = GetPlatformOptionName(optionName);
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
                return err == -1 ? SafeCloseSocket.GetLastSocketError() : SocketError.Success;
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
                int maxReadFd = FillFdSetFromSocketList(ref readSet, checkRead);

                var writeSet = new Interop.libc.fd_set();
                int maxWriteFd = FillFdSetFromSocketList(ref writeSet, checkWrite);

                var errorSet = new Interop.libc.fd_set();
                int maxErrorFd = FillFdSetFromSocketList(ref errorSet, checkError);

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

                FilterSocketListUsingFdSet(ref readSet, checkRead);
                FilterSocketListUsingFdSet(ref writeSet, checkWrite);
                FilterSocketListUsingFdSet(ref errorSet, checkError);

                return (SocketError)socketCount;
            }
        }
    }
}
