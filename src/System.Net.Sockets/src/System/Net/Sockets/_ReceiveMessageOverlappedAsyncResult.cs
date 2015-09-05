// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;
using System.Collections.Generic;

namespace System.Net.Sockets
{
    unsafe internal partial class ReceiveMessageOverlappedAsyncResult : BaseOverlappedAsyncResult
    {
        internal Internals.SocketAddress SocketAddressOriginal;
        internal Internals.SocketAddress m_SocketAddress;
        private byte[] _controlBuffer;
        internal byte[] m_MessageBuffer;
        internal SocketFlags m_flags;

        internal IPPacketInformation m_IPPacketInformation;

        internal ReceiveMessageOverlappedAsyncResult(Socket socket, Object asyncState, AsyncCallback asyncCallback) :
            base(socket, asyncState, asyncCallback)
        { }

        // TODO: remove these
        internal IntPtr GetSocketAddressSizePtr()
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(m_SocketAddress.Buffer, m_SocketAddress.GetAddressSizeOffset());
        }

        internal unsafe int GetSocketAddressSize()
        {
            return *(int*)GetSocketAddressSizePtr();
        }

        internal Internals.SocketAddress SocketAddress
        {
            get
            {
                return m_SocketAddress;
            }
        }
    }
}
