// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    // Holds common bits of mock sockets: SOL_SOCKET options, blocking state, etc.
    internal abstract class MockSocketBase
    {
        public abstract ProtocolType ProtocolType { get; }

        public bool IsBlocking { get; set; }

        public SocketError SetSockOpt(SocketOptionLevel level, SocketOptionName name, byte[] value, int valueLen)
        {
            throw new NotImplementedException();
        }

        protected abstract SocketError SetProtocolOpt(SocketOptionLevel level, SocketOptionName name, byte[] value, int valueLen);
    }
}
