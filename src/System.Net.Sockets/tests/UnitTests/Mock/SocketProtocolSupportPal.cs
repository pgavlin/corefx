// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net
{
    internal class SocketProtocolSupportPal
    {
        public static bool OSSupportsIPv6 { get { return true; } }
        public static bool OSSupportsIPv4 { get { return true; } }
    }
}
