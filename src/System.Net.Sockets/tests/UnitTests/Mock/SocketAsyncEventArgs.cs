// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

namespace System.Net.Sockets
{
    public partial class SocketAsyncEventArgs : EventArgs, IDisposable
    {
        internal int? SendPacketsDescriptorCount
        {
            get
            {
                throw new NotImplementedException();
            }
        }

        private void InitializeInternals()
        {
            throw new NotImplementedException();
        }

        private void FreeInternals(bool calledFromFinalizer)
        {
            throw new NotImplementedException();
        }

        private void SetupSingleBuffer()
        {
            throw new NotImplementedException();
        }

        private void SetupMultipleBuffers()
        {
            throw new NotImplementedException();
        }

        private void SetupSendPacketsElements()
        {
            throw new NotImplementedException();
        }

        private void InnerComplete()
        {
            throw new NotImplementedException();
        }

        private void InnerStartOperationAccept(bool userSuppliedBuffer)
        {
            throw new NotImplementedException();
        }

        private void AcceptCompletionCallback(int acceptedFileDescriptor, byte[] socketAddress, int socketAddressSize, SocketError socketError)
        {
            throw new NotImplementedException();
        }

        internal unsafe SocketError DoOperationAccept(Socket socket, SafeCloseSocket handle, SafeCloseSocket acceptHandle, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        private void InnerStartOperationConnect()
        {
            throw new NotImplementedException();
        }

        private void ConnectCompletionCallback(SocketError socketError)
        {
            throw new NotImplementedException();
        }

        internal unsafe SocketError DoOperationConnect(Socket socket, SafeCloseSocket handle, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        private void InnerStartOperationDisconnect()
        {
            throw new NotImplementedException();
        }

        internal unsafe SocketError DoOperationDisconnect(Socket socket, SafeCloseSocket handle)
        {
            throw new NotImplementedException();
        }

        private void TransferCompletionCallback(int bytesTransferred, byte[] socketAddress, int socketAddressSize, int receivedFlags, SocketError socketError)
        {
            throw new NotImplementedException();
        }

        private void InnerStartOperationReceive()
        {
            throw new NotImplementedException();
        }

        internal unsafe SocketError DoOperationReceive(SafeCloseSocket handle, out SocketFlags flags, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        private void InnerStartOperationReceiveFrom()
        {
            throw new NotImplementedException();
        }

        internal unsafe SocketError DoOperationReceiveFrom(SafeCloseSocket handle, out SocketFlags flags, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        private void InnerStartOperationReceiveMessageFrom()
        {
            throw new NotImplementedException();
        }

        private void ReceiveMessageFromCompletionCallback(int bytesTransferred, byte[] socketAddress, int socketAddressSize, int receivedFlags, IPPacketInformation ipPacketInformation, SocketError errorCode)
        {
            throw new NotImplementedException();
        }

        internal unsafe SocketError DoOperationReceiveMessageFrom(Socket socket, SafeCloseSocket handle, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        private void InnerStartOperationSend()
        {
            throw new NotImplementedException();
        }

        internal unsafe SocketError DoOperationSend(SafeCloseSocket handle, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        private void InnerStartOperationSendPackets()
        {
            throw new NotImplementedException();
        }

        internal SocketError DoOperationSendPackets(Socket socket, SafeCloseSocket handle)
        {
            throw new NotImplementedException();
        }

        private void InnerStartOperationSendTo()
        {
            throw new NotImplementedException();
        }

        internal SocketError DoOperationSendTo(SafeCloseSocket handle, out int bytesTransferred)
        {
            throw new NotImplementedException();
        }

        internal void LogBuffer(int size)
        {
            throw new NotImplementedException();
        }

        internal void LogSendPacketsBuffers(int size)
        {
            throw new NotImplementedException();
        }

        private SocketError FinishOperationAccept(Internals.SocketAddress remoteSocketAddress)
        {
            throw new NotImplementedException();
        }

        private SocketError FinishOperationConnect()
        {
            throw new NotImplementedException();
        }

        private unsafe int GetSocketAddressSize()
        {
            throw new NotImplementedException();
        }

        private unsafe void FinishOperationReceiveMessageFrom()
        {
            throw new NotImplementedException();
        }

        private void FinishOperationSendPackets()
        {
            throw new NotImplementedException();
        }

        private void CompletionCallback(int bytesTransferred, SocketError socketError)
        {
            throw new NotImplementedException();
        }
    }
}
