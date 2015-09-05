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
        // TODO: implement this

        internal void SetUnmanagedStructures(byte[] buffer, int offset, int size, Internals.SocketAddress socketAddress, SocketFlags socketFlags)
        {
            // Silence the compiler until this is implemented.
            SocketAddressOriginal = null;
            m_SocketAddress = null;
            _controlBuffer = null;
            m_MessageBuffer = null;
            m_flags = _controlBuffer == null ? SocketFlags.None : SocketFlags.None;
            m_IPPacketInformation = default(IPPacketInformation);
        }
    }
}
