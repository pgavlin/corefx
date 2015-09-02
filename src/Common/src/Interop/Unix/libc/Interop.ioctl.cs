// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Runtime.InteropServices;
using System.Text;

internal static partial class Interop
{
    internal static partial class libc
    {
        public const int FIONREAD = 0x541b;

        [DllImport(Libraries.Libc, SetLastError = true)]
        public static extern unsafe int ioctl(int d, UIntPtr request, void* argp);
    }
}
