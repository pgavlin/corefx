// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace System.Net.Sockets
{
    internal abstract class MockIpSocket : MockSocketBase
    {
        private readonly AddressFamily _addressFamily;
        private bool _dualMode;

        public sealed override AddressFamily AddressFamily { get { return _addressFamily; } }

        protected MockIpSocket(AddressFamily addressFamily)
        {
            Debug.Assert(addressFamily == AddressFamily.InterNetwork || addressFamily == AddressFamily.InterNetworkV6);

            _addressFamily = addressFamily;
            _dualMode = false;
        }

        public override int GetSockOpt(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] buffer, ref int optionLen)
        {
            if (optionLevel == SocketOptionLevel.IP)
            {
                if (_addressFamily != AddressFamily.InterNetwork && !_dualMode)
                {
                    optionLen = 0;
                    LastSocketError = SocketError.InvalidArgument;
                    return -1;
                }

                switch (optionName)
                {
                    case SocketOptionName.IPOptions:
                    case SocketOptionName.HeaderIncluded:
                    case SocketOptionName.TypeOfService:
                    case SocketOptionName.IpTimeToLive:
                    case SocketOptionName.MulticastInterface:
                    case SocketOptionName.MulticastTimeToLive:
                    case SocketOptionName.MulticastLoopback:
                    case SocketOptionName.AddMembership:
                    case SocketOptionName.DropMembership:
                    case SocketOptionName.DontFragment:
                    case SocketOptionName.AddSourceMembership:
                    case SocketOptionName.DropSourceMembership:
                    case SocketOptionName.BlockSource:
                    case SocketOptionName.UnblockSource:
                    case SocketOptionName.PacketInformation:
                        optionLen = 0;
                        LastSocketError = SocketError.Success;
                        return 0;
                }

                LastSocketError = SocketError.ProtocolOption;
                return -1;
            }
            else if (optionLevel == SocketOptionLevel.IPv6)
            {
                if (_addressFamily != AddressFamily.InterNetworkV6)
                {
                    optionLen = 0;
                    LastSocketError = SocketError.InvalidArgument;
                    return -1;
                }

                switch (optionName)
                {
                    case SocketOptionName.HopLimit:
                    case SocketOptionName.IPProtectionLevel:
                        optionLen = 0;
                        LastSocketError = SocketError.Success;
                        return 0;

                    case SocketOptionName.IPv6Only:
                        if (optionLen < 4)
                        {
                            LastSocketError = SocketError.Fault;
                            return -1;
                        }

                        optionLen = 4;

                        buffer[0] = (byte)(_dualMode ? 0 : 1);
                        buffer[1] = 0;
                        buffer[2] = 0;
                        buffer[3] = 0;
                        LastSocketError = SocketError.Success;
                        return 0;
                }

                LastSocketError = SocketError.ProtocolOption;
                return -1;
            }

            return base.GetSockOpt(optionLevel, optionName, buffer, ref optionLen);
        }

        public override int SetSockOpt(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] buffer)
        {
            if (optionLevel == SocketOptionLevel.IP)
            {
                if (_addressFamily != AddressFamily.InterNetwork && !_dualMode)
                {
                    LastSocketError = SocketError.InvalidArgument;
                    return -1;
                }

                switch (optionName)
                {
                    case SocketOptionName.IPOptions:
                    case SocketOptionName.HeaderIncluded:
                    case SocketOptionName.TypeOfService:
                    case SocketOptionName.IpTimeToLive:
                    case SocketOptionName.MulticastInterface:
                    case SocketOptionName.MulticastTimeToLive:
                    case SocketOptionName.MulticastLoopback:
                    case SocketOptionName.AddMembership:
                    case SocketOptionName.DropMembership:
                    case SocketOptionName.DontFragment:
                    case SocketOptionName.AddSourceMembership:
                    case SocketOptionName.DropSourceMembership:
                    case SocketOptionName.BlockSource:
                    case SocketOptionName.UnblockSource:
                    case SocketOptionName.PacketInformation:
                        LastSocketError = SocketError.Success;
                        return 0;
                }

                LastSocketError = SocketError.ProtocolOption;
                return -1;
            }
            else if (optionLevel == SocketOptionLevel.IPv6)
            {
                if (_addressFamily != AddressFamily.InterNetworkV6)
                {
                    LastSocketError = SocketError.InvalidArgument;
                    return -1;
                }

                switch (optionName)
                {
                    case SocketOptionName.HopLimit:
                    case SocketOptionName.IPProtectionLevel:
                        LastSocketError = SocketError.Success;
                        return 0;

                    case SocketOptionName.IPv6Only:
                        if (buffer.Length < 4)
                        {
                            LastSocketError = SocketError.Fault;
                            return -1;
                        }

                        _dualMode = buffer[0] != 0 || buffer[1] != 0 || buffer[2] != 0 || buffer[3] != 0;

                        LastSocketError = SocketError.Success;
                        return 0;
                }

                LastSocketError = SocketError.ProtocolOption;
                return -1;
            }

            return base.SetSockOpt(optionLevel, optionName, buffer);
        }
    }
}
