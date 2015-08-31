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
    //
    //  OverlappedAsyncResult - used to take care of storage for async Socket operation
    //   from the BeginSend, BeginSendTo, BeginReceive, BeginReceiveFrom calls.
    //
    internal partial class OverlappedAsyncResult : BaseOverlappedAsyncResult
    {
        //
        // internal class members
        //

        private Internals.SocketAddress _socketAddress;
        private Internals.SocketAddress _socketAddressOriginal; // needed for partial BeginReceiveFrom/EndReceiveFrom completion

        //
        // Constructor. We take in the socket that's creating us, the caller's
        // state object, and the buffer on which the I/O will be performed.
        // We save the socket and state, pin the callers's buffer, and allocate
        // an event for the WaitHandle.
        //
        internal OverlappedAsyncResult(Socket socket, Object asyncState, AsyncCallback asyncCallback) :
            base(socket, asyncState, asyncCallback)
        { }

        //
        internal Internals.SocketAddress SocketAddress
        {
            get
            {
                return _socketAddress;
            }
        }
        //
        internal Internals.SocketAddress SocketAddressOriginal
        {
            get
            {
                return _socketAddressOriginal;
            }
            set
            {
                _socketAddressOriginal = value;
            }
        }
    }; // class OverlappedAsyncResult
} // namespace System.Net.Sockets
