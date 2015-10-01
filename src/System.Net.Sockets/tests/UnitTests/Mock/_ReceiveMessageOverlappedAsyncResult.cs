// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    internal partial class ReceiveMessageOverlappedAsyncResult : BaseOverlappedAsyncResult
    {
        internal int GetSocketAddressSize()
        {
            throw new NotImplementedException();
        }
    }
}
