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
        //PostCompletion returns the result object to be set before the user's callback is invoked.
        internal virtual object PostCompletion(int numBytes)
        {
            return numBytes;
        }

        //
        // This method is called after an asynchronous call is made for the user,
        // it checks and acts accordingly if the IO:
        // 1) completed synchronously.
        // 2) was pended.
        // 3) failed.
        //
        internal unsafe SocketError CheckAsyncCallOverlappedResult(SocketError errorCode)
        {
            //
            // Check if the Async IO call:
            // 1) was pended.
            // 2) completed synchronously.
            // 3) failed.
            //

            GlobalLog.Print(
                "BaseOverlappedAsyncResult#" + Logging.HashString(this) +
                "::CheckAsyncCallOverlappedResult(" + errorCode.ToString() + ")");

            switch (errorCode)
            {
                //
                // ignore cases in which a completion packet will be queued:
                // we'll deal with this IO in the callback
                //
                case SocketError.Success:
                case SocketError.IOPending:
                    //
                    // ignore, do nothing.
                    //
                    return SocketError.Success;

                //
                // in the remaining cases a completion packet will NOT be queued:
                // we'll have to call the callback explicitly signaling an error
                //
                default:
                    //
                    // call the callback with error code
                    //

                    ErrorCode = (int)errorCode;
                    Result = -1;

                    ReleaseUnmanagedStructures();  // Additional release for the completion that won't happen.
                    break;
            }

            return errorCode;
        }
    }
}
