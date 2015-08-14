// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using System.Text;

using socklen_t = System.UInt32;

internal static partial class Interop
{
    internal static partial class libc
    {
        public unsafe struct msghdr
        {
            public void* msg_name;
            public socklen_t msg_namelen;
            public iovec* msg_iov;
            public IntPtr msg_iovlen;
            public void* msg_control;
            public IntPtr msg_controllen;
            public int msg_flags;
        }
    }
}
