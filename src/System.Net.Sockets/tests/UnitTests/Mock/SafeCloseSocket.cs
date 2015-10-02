// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;

namespace System.Net.Sockets
{
    internal sealed partial class SafeCloseSocket :
#if DEBUG
        DebugSafeHandleMinusOneIsInvalid
#else
        SafeHandleMinusOneIsInvalid
#endif
    {
        public int HandleId
        {
            get
            {
                return (int)handle;
            }
        }

        public unsafe static SafeCloseSocket CreateSocket(int handleId)
        {
            return CreateSocket(InnerSafeCloseSocket.CreateSocket(handleId));
        }

        public unsafe static SafeCloseSocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
        {
            return CreateSocket(InnerSafeCloseSocket.CreateSocket(addressFamily, socketType, protocolType));
        }

        public unsafe static SafeCloseSocket Accept(SafeCloseSocket socketHandle, byte[] socketAddress, ref int socketAddressSize)
        {
            return CreateSocket(InnerSafeCloseSocket.Accept(socketHandle, socketAddress, ref socketAddressSize));
        }

        private void InnerReleaseHandle()
        {
        }

        internal sealed partial class InnerSafeCloseSocket : SafeHandleMinusOneIsInvalid
        {
            private unsafe SocketError InnerReleaseHandle()
            {
                int err = MockSocketBase.CloseSocket((int)handle);
                return err == -1 ? SocketPal.GetLastSocketError() : SocketError.Success;
            }

            public static InnerSafeCloseSocket CreateSocket(int handleId)
            {
                var res = new InnerSafeCloseSocket();
                res.SetHandle((IntPtr)handleId);
                return res;
            }

            public static unsafe InnerSafeCloseSocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
            {
                int handleId = MockSocketBase.CreateSocket(addressFamily, socketType, protocolType);

                var res = new InnerSafeCloseSocket();
                res.SetHandle((IntPtr)handleId);
                return res;
            }

            public static unsafe InnerSafeCloseSocket Accept(SafeCloseSocket socketHandle, byte[] socketAddress, ref int socketAddressLen)
            {
                throw new NotImplementedException();
            }
        }
    }
}
