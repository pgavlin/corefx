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

        public static SocketError LastSocketError
        {
            get { return s_lastSocketError; }
            protected set { LastSocketError = value; }
        }

        public abstract AddressFamily AddressFamily { get; }
        public abstract SocketType SocketType { get; }
        public abstract ProtocolType ProtocolType { get; }

        public virtual int GetSockOpt(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] buffer, ref int optionLen)
        {
            if (optionLevel != SocketOptionLevel.Socket)
            {
                optionLen = 0;
                LastSocketError = SocketError.InvalidArgument;
                return -1;
            }

            // TODO: support options
            switch (optionName)
            {
                case SocketOptionName.Debug:
                case SocketOptionName.AcceptConnection:
                case SocketOptionName.ReuseAddress:
                case SocketOptionName.KeepAlive:
                case SocketOptionName.DontRoute:
                case SocketOptionName.Broadcast:
                case SocketOptionName.UseLoopback:
                case SocketOptionName.Linger:
                case SocketOptionName.OutOfBandInline:
                case SocketOptionName.DontLinger:
                case SocketOptionName.ExclusiveAddressUse:
                case SocketOptionName.SendBuffer:
                case SocketOptionName.ReceiveBuffer:
                case SocketOptionName.SendLowWater:
                case SocketOptionName.ReceiveLowWater:
                case SocketOptionName.SendTimeout:
                case SocketOptionName.ReceiveTimeout:
                case SocketOptionName.Error:
                case SocketOptionName.Type:
                case SocketOptionName.MaxConnections:
                    optionLen = 0;
                    LastSocketError = SocketError.Success;
                    return 0;
            }

            LastSocketError = SocketError.ProtocolOption;
            return -1;
        }

        public virtual int SetSockOpt(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] buffer)
        {
            if (optionLevel != SocketOptionLevel.Socket)
            {
                LastSocketError = SocketError.InvalidArgument;
                return -1;
            }

            // TODO: support options
            switch (optionName)
            {
                case SocketOptionName.Debug:
                case SocketOptionName.AcceptConnection:
                case SocketOptionName.ReuseAddress:
                case SocketOptionName.KeepAlive:
                case SocketOptionName.DontRoute:
                case SocketOptionName.Broadcast:
                case SocketOptionName.UseLoopback:
                case SocketOptionName.Linger:
                case SocketOptionName.OutOfBandInline:
                case SocketOptionName.DontLinger:
                case SocketOptionName.ExclusiveAddressUse:
                case SocketOptionName.SendBuffer:
                case SocketOptionName.ReceiveBuffer:
                case SocketOptionName.SendLowWater:
                case SocketOptionName.ReceiveLowWater:
                case SocketOptionName.SendTimeout:
                case SocketOptionName.ReceiveTimeout:
                case SocketOptionName.Error:
                case SocketOptionName.Type:
                case SocketOptionName.MaxConnections:
                    LastSocketError = SocketError.Success;
                    return 0;
            }

            LastSocketError = SocketError.ProtocolOption;
            return -1;
        }

        private static int CreateTcpSocket(AddressFamily addressFamily, SocketType socketType)
        {
            if (socketType != SocketType.Stream)
            {
                // TODO: validate this error
                LastSocketError = SocketError.InvalidArgument;
                return -1;
            }

            int handleId = s_socketTable.AllocateHandle(af => new MockTcpSocket(af), addressFamily);
            if (handleId == -1)
            {
                LastSocketError = SocketError.TooManyOpenSockets;
                return -1;
            }

            LastSocketError = SocketError.Success;
            return handleId;
        }

        private static int CreateUdpSocket(AddressFamily addressFamily, SocketType socketType)
        {
            if (socketType != SocketType.Dgram)
            {
                // TODO: validate this error
                LastSocketError = SocketError.InvalidArgument;
                return -1;
            }

            int handleId = s_socketTable.AllocateHandle(af => new MockUdpSocket(af), addressFamily);
            if (handleId == -1)
            {
                LastSocketError = SocketError.TooManyOpenSockets;
                return -1;
            }

            LastSocketError = SocketError.Success;
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
                LastSocketError = SocketError.AddressFamilyNotSupported;
                return -1;
            }

            switch (protocolType)
            {
                case ProtocolType.Tcp:
                    return CreateTcpSocket(addressFamily, socketType);

                case ProtocolType.Udp:
                    return CreateUdpSocket(addressFamily, socketType);

                default:
                    LastSocketError = SocketError.ProtocolFamilyNotSupported;
                    return -1;
            }
        }

        public static int CloseSocket(int handleId)
        {
            MockSocketBase socket;
            if (!s_socketTable.TryGetValue(handleId, out socket))
            {
                LastSocketError = SocketError.NotSocket;
                return -1;
            }

            s_socketTable.FreeHandle(handleId);
            return 0;
        }

        public static int GetSockOpt(int handleId, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] buffer, ref int optionLen)
        {
            MockSocketBase socket;
            if (!s_socketTable.TryGetValue(handleId, out socket))
            {
                LastSocketError = SocketError.NotSocket;
                return -1;
            }

            return socket.GetSockOpt(optionLevel, optionName, buffer, ref optionLen);
        }

        public static int SetSockOpt(int handleId, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] buffer)
        {
            MockSocketBase socket;
            if (!s_socketTable.TryGetValue(handleId, out socket))
            {
                LastSocketError = SocketError.NotSocket;
                return -1;
            }

            return socket.SetSockOpt(optionLevel, optionName, buffer);
        }
    }
}
