// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    internal abstract class MockIpSocket : MockSocketBase
    {
        private AddressFamily _addressFamily;

        public sealed override AddressFamily AddressFamily { get { return _addressFamily; } }

        protected MockIpSocket(AddressFamily addressFamily)
        {
            _addressFamily = addressFamily;
        }
    }
}
