// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    // AcceptOverlappedAsyncResult - used to take care of storage for async Socket BeginAccept call.
    internal partial class AcceptOverlappedAsyncResult : BaseOverlappedAsyncResult
    {
        internal Socket AcceptSocket
        {
            set
            {
                // TODO: implement
                throw new NotImplementedException();
            }
        }

        internal override object PostCompletion(int numBytes)
        {
            // TODO: implement
            throw new NotImplementedException();
        }
    }
}
