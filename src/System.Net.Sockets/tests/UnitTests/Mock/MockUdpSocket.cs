// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    internal sealed class MockUdpSocket : MockIpSocket
    {
        public override SocketType SocketType { get { return SocketType.Dgram; } }
        public override ProtocolType ProtocolType { get { return ProtocolType.Udp; } }

        public MockUdpSocket(AddressFamily addressFamily)
            : base(addressFamily)
        {
        }

        public override int GetSockOpt(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] buffer, ref int optionLen)
        {
            if (optionLevel != SocketOptionLevel.Udp)
            {
                return base.GetSockOpt(optionLevel, optionName, buffer, ref optionLen);
            }

            // TODO: support options
            switch (optionName)
            {
                case SocketOptionName.NoChecksum:
                case SocketOptionName.ChecksumCoverage:
                case SocketOptionName.UpdateAcceptContext:
                case SocketOptionName.UpdateConnectContext:
                    optionLen = 0;
                    LastSocketError = SocketError.Success;
                    return 0;
            }

            LastSocketError = SocketError.ProtocolOption;
            return -1;
        }

        public override int SetSockOpt(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] buffer)
        {
            if (optionLevel != SocketOptionLevel.Udp)
            {
                return base.SetSockOpt(optionLevel, optionName, buffer);
            }

            // TODO: support options
            switch (optionName)
            {
                case SocketOptionName.NoChecksum:
                case SocketOptionName.ChecksumCoverage:
                case SocketOptionName.UpdateAcceptContext:
                case SocketOptionName.UpdateConnectContext:
                    LastSocketError = SocketError.Success;
                    return 0;
            }

            LastSocketError = SocketError.ProtocolOption;
            return -1;
        }
    }
}
