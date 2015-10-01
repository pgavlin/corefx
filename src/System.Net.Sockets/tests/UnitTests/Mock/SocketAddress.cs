// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    internal unsafe struct MockSocketAddress
    {
        public const int IPv6AddressSize = 16;
        public const int IPv4AddressSize = 4;

        public AddressFamily AddressFamily;
        public ushort Port;
        public fixed byte Address[IPv6AddressSize];
    }
}
