// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    // OverlappedAsyncResult
    //
    // This class is used to take care of storage for async Socket operation
    // from the BeginSend, BeginSendTo, BeginReceive, BeginReceiveFrom calls.
    internal partial class OverlappedAsyncResult : BaseOverlappedAsyncResult
    {
        internal int GetSocketAddressSize()
        {
            throw new NotImplementedException();
        }
    }
}
