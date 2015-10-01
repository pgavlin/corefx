// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Sockets;

namespace System.Net
{
    internal static class SocketAddressPal
    {
        public const int IPv6AddressSize = -1;
        public const int IPv4AddressSize = -1;
        public const int DataOffset = 0;

        public static unsafe AddressFamily GetAddressFamily(byte[] buffer)
        {
            throw new NotImplementedException();
        }

        public static unsafe void SetAddressFamily(byte[] buffer, AddressFamily family)
        {
            throw new NotImplementedException();
        }

        public static unsafe ushort GetPort(byte[] buffer)
        {
            throw new NotImplementedException();
        }

        public static unsafe void SetPort(byte[] buffer, ushort port)
        {
            throw new NotImplementedException();
        }

        public static unsafe uint GetIPv4Address(byte[] buffer)
        {
            throw new NotImplementedException();
        }

        public static unsafe void GetIPv6Address(byte[] buffer, byte[] address, out uint scope)
        {
            throw new NotImplementedException();
        }

        public static unsafe void SetIPv4Address(byte[] buffer, uint address)
        {
            throw new NotImplementedException();
        }

        public static unsafe void SetIPv6Address(byte[] buffer, byte[] address, uint scope)
        {
            throw new NotImplementedException();
        }
    }
}
