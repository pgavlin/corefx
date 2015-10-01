// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    internal enum SendPacketsElementFlags : uint
    {
        File = 0,
        Memory = 1,
        EndOfPacket = 2,
    }
}
