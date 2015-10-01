// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;
using System.Collections.Generic;

namespace System.Net.Sockets
{
    internal static partial class SocketPal
    {
        // The API that uses this information is not supported on *nix, and will throw
        // PlatformNotSupportedException instead.
        public const int ProtocolInformationSize = 0;

        public const bool SupportsMultipleConnectAttempts = true;

        public static SocketError GetLastSocketError()
        {
            throw new NotImplementedException();
        }

        public static SafeCloseSocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
        {
            return SafeCloseSocket.CreateSocket(addressFamily, socketType, protocolType);
        }

        public static unsafe SafeCloseSocket CreateSocket(SocketInformation socketInformation, out AddressFamily addressFamily, out SocketType socketType, out ProtocolType protocolType)
        {
            throw new NotImplementedException();
        }

        public static SocketError SetBlocking(SafeCloseSocket handle, bool shouldBlock, out bool willBlock)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError GetSockName(SafeCloseSocket handle, byte[] buffer, ref int nameLen)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError GetAvailable(SafeCloseSocket handle, out int available)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError GetPeerName(SafeCloseSocket handle, byte[] buffer, ref int nameLen)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError Bind(SafeCloseSocket handle, byte[] buffer, int nameLen)
        {
            throw new NotImplementedException();
        }

        public static SocketError Listen(SafeCloseSocket handle, int backlog)
        {
            throw new NotImplementedException();
        }

        public static SafeCloseSocket Accept(SafeCloseSocket handle, byte[] buffer, ref int nameLen)
        {
            throw new NotImplementedException();
        }

        public static SocketError Connect(SafeCloseSocket handle, byte[] socketAddress, int socketAddressLen)
        {
            throw new NotImplementedException();
        }

        public static SocketError Disconnect(Socket socket, SafeCloseSocket handle, bool reuseSocket)
        {
            throw new NotImplementedException();
        }

        public static SocketError Send(SafeCloseSocket handle, BufferOffsetSize[] buffers, SocketFlags socketFlags, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        public static SocketError Send(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        public static SocketError Send(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        public static SocketError SendTo(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, byte[] socketAddress, int socketAddressLen, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        public static SocketError Receive(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, ref SocketFlags socketFlags, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        public static SocketError Receive(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        public static SocketError ReceiveMessageFrom(Socket socket, SafeCloseSocket handle, byte[] buffer, int offset, int count, ref SocketFlags socketFlags, Internals.SocketAddress socketAddress, out Internals.SocketAddress receiveAddress, out IPPacketInformation ipPacketInformation, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        public static SocketError ReceiveFrom(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, byte[] socketAddress, ref int socketAddressLen, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        public static SocketError Ioctl(SafeCloseSocket handle, int ioControlCode, byte[] optionInValue, byte[] optionOutValue, out int optionLength)
        {
            throw new NotImplementedException();
        }

        public static SocketError IoctlInternal(SafeCloseSocket handle, IOControlCode ioControlCode, IntPtr optionInValue, int inValueLength, IntPtr optionOutValue, int outValueLength, out int optionLength)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError SetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, int optionValue)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError SetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue)
        {
            throw new NotImplementedException();
        }

        public static void SetReceivingDualModeIPv4PacketInformation(Socket socket)
        {
            socket.SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
        }

        public static unsafe SocketError SetMulticastOption(SafeCloseSocket handle, SocketOptionName optionName, MulticastOption optionValue)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError SetIPv6MulticastOption(SafeCloseSocket handle, SocketOptionName optionName, IPv6MulticastOption optionValue)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError SetLingerOption(SafeCloseSocket handle, LingerOption optionValue)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError GetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, out int optionValue)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError GetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue, ref int optionLength)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError GetMulticastOption(SafeCloseSocket handle, SocketOptionName optionName, out MulticastOption optionValue)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError GetIPv6MulticastOption(SafeCloseSocket handle, SocketOptionName optionName, out IPv6MulticastOption optionValue)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError GetLingerOption(SafeCloseSocket handle, out LingerOption optionValue)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError Poll(SafeCloseSocket handle, int microseconds, SelectMode mode, out bool status)
        {
            throw new NotImplementedException();
        }

        public static unsafe SocketError Select(IList checkRead, IList checkWrite, IList checkError, int microseconds)
        {
            throw new NotImplementedException();
        }

        public static SocketError Shutdown(SafeCloseSocket handle, bool isConnected, bool isDisconnected, SocketShutdown how)
        {
            throw new NotImplementedException();
        }

        public static SocketError ConnectAsync(Socket socket, SafeCloseSocket handle, byte[] socketAddress, int socketAddressLen, ConnectOverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError DisconnectAsync(Socket socket, SafeCloseSocket handle, bool reuseSocket, DisconnectOverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError SendAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError SendAsync(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError SendAsync(SafeCloseSocket handle, BufferOffsetSize[] buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError SendToAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, Internals.SocketAddress socketAddress, OverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError ReceiveAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError ReceiveAsync(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError ReceiveFromAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, Internals.SocketAddress socketAddress, OverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError ReceiveMessageFromAsync(Socket socket, SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, Internals.SocketAddress socketAddress, ReceiveMessageOverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }

        public static SocketError AcceptAsync(Socket socket, SafeCloseSocket handle, SafeCloseSocket acceptHandle, int receiveSize, int socketAddressSize, AcceptOverlappedAsyncResult asyncResult)
        {
            throw new NotImplementedException();
        }
    }
}
