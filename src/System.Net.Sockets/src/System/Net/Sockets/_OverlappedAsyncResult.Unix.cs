// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics;

namespace System.Net.Sockets
{
    internal partial class OverlappedAsyncResult : BaseOverlappedAsyncResult
    {
        int _socketAddressSize;

        internal int GetSocketAddressSize()
        {
            return _socketAddressSize;
        }

        public new void CompletionCallback(int numBytes, byte[] socketAddress, int socketAddressSize, SocketError errorCode)
        {
            ErrorCode = (int)errorCode;

            if (_socketAddress != null)
            {
                Debug.Assert(socketAddress == null || _socketAddress.Buffer == socketAddress);
                _socketAddressSize = socketAddressSize;
            }

            InvokeCallback(PostCompletion(numBytes));
        }
    }
}
