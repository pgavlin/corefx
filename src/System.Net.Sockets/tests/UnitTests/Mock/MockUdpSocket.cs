// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    internal sealed class MockUdpSocket : MockIpSocket
    {
        public sealed override SocketType SocketType { get { return SocketType.Dgram; } }
        public sealed override ProtocolType ProtocolType { get { return ProtocolType.Udp; } }

        public MockUdpSocket(AddressFamily addressFamily)
            : base(addressFamily)
        {
        }
    }
}
