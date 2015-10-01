// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Threading;

namespace System.Net.Sockets
{
    // Holds common bits of mock sockets: SOL_SOCKET options, blocking state, etc.
    internal abstract class MockSocketBase
    {
        private const int MaxSockets = 4096;

        [ThreadStatic]
        private static SocketError s_lastSocketError;

        private readonly static HandleTable<MockSocketBase, AddressFamily> s_socketTable = new HandleTable<MockSocketBase, AddressFamily>(MaxSockets);

        public abstract AddressFamily AddressFamily { get; }
        public abstract SocketType SocketType { get; }
        public abstract ProtocolType ProtocolType { get; }

        private static int CreateTcpSocket(AddressFamily addressFamily, SocketType socketType)
        {
            if (socketType != SocketType.Stream)
            {
                // TODO: validate this error
                s_lastSocketError = SocketError.InvalidArgument;
                return -1;
            }

            int handleId = s_socketTable.AllocateHandle(af => new MockTcpSocket(af), addressFamily);
            if (handleId == -1)
            {
                s_lastSocketError = SocketError.TooManyOpenSockets;
                return -1;
            }

            s_lastSocketError = SocketError.Success;
            return handleId;
        }

        private static int CreateUdpSocket(AddressFamily addressFamily, SocketType socketType)
        {
            if (socketType != SocketType.Dgram)
            {
                // TODO: validate this error
                s_lastSocketError = SocketError.InvalidArgument;
                return -1;
            }

            int handleId = s_socketTable.AllocateHandle(af => new MockUdpSocket(af), addressFamily);
            if (handleId == -1)
            {
                s_lastSocketError = SocketError.TooManyOpenSockets;
                return -1;
            }

            s_lastSocketError = SocketError.Success;
            return handleId;
        }

        public static SocketError GetLastSocketError()
        {
            return s_lastSocketError;
        }

        public static int CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
        {
            if (addressFamily != AddressFamily.InterNetwork && addressFamily != AddressFamily.InterNetworkV6)
            {
                s_lastSocketError = SocketError.AddressFamilyNotSupported;
                return -1;
            }

            switch (protocolType)
            {
                case ProtocolType.Tcp:
                    return CreateTcpSocket(addressFamily, socketType);

                case ProtocolType.Udp:
                    return CreateUdpSocket(addressFamily, socketType);

                default:
                    s_lastSocketError = SocketError.ProtocolFamilyNotSupported;
                    return -1;
            }
        }
    }
}
