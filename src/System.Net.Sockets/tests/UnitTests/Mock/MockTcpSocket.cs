// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    internal sealed class MockTcpSocket : MockIpSocket
    {
        public sealed override SocketType SocketType { get { return SocketType.Stream; } }
        public sealed override ProtocolType ProtocolType { get { return ProtocolType.Tcp; } }

        public MockTcpSocket(AddressFamily addressFamily)
            : base(addressFamily)
        {
        }
    }
}
