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

        public void CompletionCallback(int numBytes, byte[] socketAddress, int socketAddressSize, int receivedFlags, SocketError errorCode)
        {
            if (_socketAddress != null)
            {
                Debug.Assert(socketAddress == null || _socketAddress.Buffer == socketAddress);
                _socketAddressSize = socketAddressSize;
            }

            base.CompletionCallback(numBytes, errorCode);
        }
    }
}
