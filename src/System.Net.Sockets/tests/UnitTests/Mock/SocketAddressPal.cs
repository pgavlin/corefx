// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Net.Sockets;

namespace System.Net
{
    internal static class SocketAddressPal
    {
        public const int IPv6AddressSize = MockSocketAddress.IPv6AddressSize;
        public const int IPv4AddressSize = MockSocketAddress.IPv4AddressSize;
        public const int DataOffset = 0;

        public static unsafe AddressFamily GetAddressFamily(byte[] buffer)
        {
            Debug.Assert(buffer.Length >= sizeof(MockSocketAddress));
            
            fixed (byte* rawAddress = buffer)
            {
                return ((MockSocketAddress*)rawAddress)->AddressFamily;
            }
        }

        public static unsafe void SetAddressFamily(byte[] buffer, AddressFamily family)
        {
            Debug.Assert(buffer.Length >= sizeof(MockSocketAddress));
            
            fixed (byte* rawAddress = buffer)
            {
                ((MockSocketAddress*)rawAddress)->AddressFamily = family;
            }
        }

        public static unsafe ushort GetPort(byte[] buffer)
        {
            Debug.Assert(buffer.Length >= sizeof(MockSocketAddress));
            
            fixed (byte* rawAddress = buffer)
            {
                return ((MockSocketAddress*)rawAddress)->Port;
            }
        }

        public static unsafe void SetPort(byte[] buffer, ushort port)
        {
            Debug.Assert(buffer.Length >= sizeof(MockSocketAddress));
            
            fixed (byte* rawAddress = buffer)
            {
                ((MockSocketAddress*)rawAddress)->Port = family;
            }
        }

        public static unsafe uint GetIPv4Address(byte[] buffer)
        {
            Debug.Assert(buffer.Length >= sizeof(MockSocketAddress));
            
            fixed (byte* rawAddress = buffer)
            {
                var addr = (MockSocketAddres*)rawAddress;
                Debug.Assert(addr.AddressFamily == AddressFamily.InterNetwork);

                return (uint)addr->Address[0] | (uint)(addr->Address[1] << 8) | (uint)(addr->Address[2] << 16) | (uint)(addr->Address[3] << 24);
            }
        }

        public static unsafe void GetIPv6Address(byte[] buffer, byte[] address, out uint scope)
        {
            Debug.Assert(buffer.Length >= sizeof(MockSocketAddress));
            
            fixed (byte* rawAddress = buffer)
            {
                var addr = (MockSocketAddres*)rawAddress;
                Debug.Assert(addr.AddressFamily == AddressFamily.InterNetworkV6);

                for (int i = 0; i < MockSocketAddress.IPv6AddressBytes)
                {
                    address[i] = addr->Address[i];
                }
            }
        }

        public static unsafe void SetIPv4Address(byte[] buffer, uint address)
        {
            Debug.Assert(buffer.Length >= sizeof(MockSocketAddress));
            
            fixed (byte* rawAddress = buffer)
            {
                var addr = (MockSocketAddres*)rawAddress;
                Debug.Assert(addr.AddressFamily == AddressFamily.InterNetwork);

                addr->Address[0] = (byte)address;
                addr->Address[1] = (byte)(address >> 8);
                addr->Address[2] = (byte)(address >> 16);
                addr->Address[3] = (byte)(address >> 24);
            }
        }

        public static unsafe void SetIPv6Address(byte[] buffer, byte[] address, uint scope)
        {
            Debug.Assert(buffer.Length >= sizeof(MockSocketAddress));
            
            fixed (byte* rawAddress = buffer)
            {
                var addr = (MockSocketAddres*)rawAddress;
                Debug.Assert(addr.AddressFamily == AddressFamily.InterNetworkV6);

                for (int i = 0; i < MockSocketAddress.IPv6AddressBytes)
                {
                    addr->Address[i] = address[i];
                }
            }
        }
    }
}
