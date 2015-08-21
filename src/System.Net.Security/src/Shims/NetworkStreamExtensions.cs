// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    internal static class NetworkStreamExtensions
    {
        /// <devdoc>
        ///    <para>
        ///       Performs a sync Write of an array of buffers.
        ///    </para>
        /// </devdoc>
        internal static void MultipleWrite(this NetworkStream thisStream, BufferOffsetSize[] buffers)
        {
            throw new NotImplementedException("NetworkStreamExtensions Shim");
        }

        /// <devdoc>
        ///    <para>
        ///       Starts off an async Write of an array of buffers.
        ///    </para>
        /// </devdoc>
        internal static IAsyncResult BeginMultipleWrite(
            this NetworkStream thisStream,
            BufferOffsetSize[] buffers,
            AsyncCallback callback,
            Object state)
        {
            throw new NotImplementedException("NetworkStreamExtensions Shim");
        }

        internal static void EndMultipleWrite(this NetworkStream thisStream, IAsyncResult asyncResult)
        {
            throw new NotImplementedException("NetworkStreamExtensions Shim");
        }
    }
}

