// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace System.Net.Sockets
{
    internal partial class OverlappedAsyncResult : BaseOverlappedAsyncResult
    {
        public new void CompletionCallback(int numBytes, byte[] socketAddress, int socketAddressLen, SocketError errorCode)
        {
            ErrorCode = (int)errorCode;

            if (_socketAddress != null)
            {
                Debug.Assert(socketAddress == null || _socketAddress.Buffer == socketAddress);
                _socketAddress.InternalSize = socketAddressLen;
            }

            InvokeCallback(PostCompletion(numBytes));
        }
    }
}
