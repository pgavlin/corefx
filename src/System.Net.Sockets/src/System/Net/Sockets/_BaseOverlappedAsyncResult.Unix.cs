// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;

namespace System.Net.Sockets
{
    //
    //  BaseOverlappedAsyncResult - used to enable async Socket operation
    //  such as the BeginSend, BeginSendTo, BeginReceive, BeginReceiveFrom, BeginSendFile,
    //  BeginAccept, calls.
    //
    internal partial class BaseOverlappedAsyncResult : ContextAwareResult
    {
        //
        // Constructor. We take in the socket that's creating us, the caller's
        // state object, and callback. We save the socket and state, and allocate
        // an event for the WaitHandle.
        //
        public BaseOverlappedAsyncResult(Socket socket, Object asyncState, AsyncCallback asyncCallback)
            : base(socket, asyncState, asyncCallback)
        {
            GlobalLog.Print(
                "BaseOverlappedAsyncResult#" + Logging.HashString(this) +
                "(Socket#" + Logging.HashString(socket) + ")");
        }

        public void CompletionCallback(int numBytes, byte[] socketAddress, int socketAddressLen, SocketError errorCode)
        {
            ErrorCode = (int)errorCode;
            InvokeCallback(PostCompletion(numBytes));
        }

        private void ReleaseUnmanagedStructures()
        {
        }

        // TODO: remove these
        internal SafeNativeOverlapped NativeOverlapped
        {
            get
            {
                return null;
            }
        }

        internal SafeHandle OverlappedHandle
        {
            get
            {
                return null;
            }
        }

        internal void SetUnmanagedStructures(object objectsToPin)
        {
        }

        protected virtual void ForceReleaseUnmanagedStructures()
        {
        }
    }
}
