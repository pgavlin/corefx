// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;

namespace System.Net.Sockets
{
    public partial class SocketAsyncEventArgs : EventArgs, IDisposable
    {
        private int _acceptedFileDescriptor;
        private int _socketAddressSize;
        private SocketFlags _receivedFlags;

        internal int? SendPacketsDescriptorCount { get { return null; } }

        private void InitializeInternals()
        {
            // No-op for *nix.
        }

        private void FreeInternals(bool calledFromFinalizer)
        {
            // No-op for *nix.
        }

        private void SetupSingleBuffer()
        {
            // No-op for *nix.
        }

        private void SetupMultipleBuffers()
        {
            // No-op for *nix.
        }

        private void SetupSendPacketsElements()
        {
            // No-op for *nix.
        }

        private void InnerComplete()
        {
            // No-op for *nix.
        }

        private void InnerStartOperationAccept(bool userSuppliedBuffer)
        {
            _acceptedFileDescriptor = -1;
        }

        private void AcceptCompletionCallback(int acceptedFileDescriptor, byte[] socketAddress, int socketAddressSize, SocketError socketError)
        {
            // TODO: receive bytes on socket if requested

            _acceptedFileDescriptor = acceptedFileDescriptor;
            Debug.Assert(socketAddress == null || socketAddress == m_AcceptBuffer);
            m_AcceptAddressBufferCount = socketAddressSize;

            CompletionCallback(0, socketError);
        }

        internal unsafe SocketError DoOperationAccept(Socket socket, SafeCloseSocket handle, SafeCloseSocket acceptHandle, out int bytesTransferred)
        {
            Debug.Assert(acceptHandle == null);

            bytesTransferred = 0;

            return handle.AsyncContext.AcceptAsync(m_Buffer ?? m_AcceptBuffer, m_AcceptAddressBufferCount / 2, AcceptCompletionCallback);
        }

        private void InnerStartOperationConnect()
        {
            // No-op for *nix.
        }

        private void ConnectCompletionCallback(SocketError socketError)
        {
            CompletionCallback(0, socketError);
        }

        internal unsafe SocketError DoOperationConnect(Socket socket, SafeCloseSocket handle, out int bytesTransferred)
        {
            bytesTransferred = 0;

            return handle.AsyncContext.ConnectAsync(m_SocketAddress.Buffer, m_SocketAddress.Size, ConnectCompletionCallback);
        }

        private void InnerStartOperationDisconnect()
        {
            throw new PlatformNotSupportedException();
        }

        internal unsafe SocketError DoOperationDisconnect(Socket socket, SafeCloseSocket handle)
        {
            throw new PlatformNotSupportedException();
        }

        private void TransferCompletionCallback(int bytesTransferred, byte[] socketAddress, int socketAddressSize, int receivedFlags, SocketError socketError)
        {
            Debug.Assert(socketAddress == null || socketAddress == m_SocketAddress.Buffer);
            _socketAddressSize = socketAddressSize;
            _receivedFlags = SocketPal.GetSocketFlags(receivedFlags);

            CompletionCallback(bytesTransferred, socketError);
        }

        private void InnerStartOperationReceive()
        {
            _receivedFlags = System.Net.Sockets.SocketFlags.None;
            _socketAddressSize = 0;
        }

        internal unsafe SocketError DoOperationReceive(SafeCloseSocket handle, out SocketFlags flags, out int bytesTransferred)
        {
            int platformFlags = SocketPal.GetPlatformSocketFlags(m_SocketFlags);

            SocketError errorCode;
            if (m_Buffer != null)
            {
                errorCode = handle.AsyncContext.ReceiveAsync(m_Buffer, m_Offset, m_Count, platformFlags, TransferCompletionCallback);
            }
            else
            {
                errorCode = handle.AsyncContext.ReceiveAsync(m_BufferList, platformFlags, TransferCompletionCallback);
            }

            flags = m_SocketFlags;
            bytesTransferred = 0;
            return errorCode;
        }

        private void InnerStartOperationReceiveFrom()
        {
            _receivedFlags = System.Net.Sockets.SocketFlags.None;
            _socketAddressSize = 0;
        }

        internal unsafe SocketError DoOperationReceiveFrom(SafeCloseSocket handle, out SocketFlags flags, out int bytesTransferred)
        {
            int platformFlags = SocketPal.GetPlatformSocketFlags(m_SocketFlags);

            SocketError errorCode;
            if (m_Buffer != null)
            {
                errorCode = handle.AsyncContext.ReceiveFromAsync(m_Buffer, m_Offset, m_Count, platformFlags, m_SocketAddress.Buffer, m_SocketAddress.Size, TransferCompletionCallback);
            }
            else
            {
                errorCode = handle.AsyncContext.ReceiveFromAsync(m_BufferList, platformFlags, m_SocketAddress.Buffer, m_SocketAddress.Size, TransferCompletionCallback);
            }

            flags = m_SocketFlags;
            bytesTransferred = 0;
            return errorCode;
        }

        private void InnerStartOperationReceiveMessageFrom()
        {
            _receiveMessageFromPacketInfo = default(IPPacketInformation);
            _receivedFlags = System.Net.Sockets.SocketFlags.None;
            _socketAddressSize = 0;
        }

        private void ReceiveMessageFromCompletionCallback(int bytesTransferred, byte[] socketAddress, int socketAddressSize, int receivedFlags, IPPacketInformation ipPacketInformation, SocketError errorCode)
        {
            Debug.Assert(m_SocketAddress != null);
            Debug.Assert(socketAddress == null || m_SocketAddress.Buffer == socketAddress);

            _socketAddressSize = socketAddressSize;
            _receivedFlags = SocketPal.GetSocketFlags(receivedFlags);
            _receiveMessageFromPacketInfo = ipPacketInformation;

            CompletionCallback(bytesTransferred, errorCode);
        }

        internal unsafe SocketError DoOperationReceiveMessageFrom(Socket socket, SafeCloseSocket handle, out int bytesTransferred)
        {
            int platformFlags = SocketPal.GetPlatformSocketFlags(m_SocketFlags);

            bool isIPv4, isIPv6;
            Socket.GetIPProtocolInformation(socket.AddressFamily, m_SocketAddress, out isIPv4, out isIPv6);

            bytesTransferred = 0;
            return handle.AsyncContext.ReceiveMessageFromAsync(m_Buffer, m_Offset, m_Count, platformFlags, m_SocketAddress.Buffer, m_SocketAddress.Size, isIPv4, isIPv6, ReceiveMessageFromCompletionCallback);
        }

        private void InnerStartOperationSend()
        {
            _receivedFlags = System.Net.Sockets.SocketFlags.None;
            _socketAddressSize = 0;
        }

        internal unsafe SocketError DoOperationSend(SafeCloseSocket handle, out int bytesTransferred)
        {
            int platformFlags = SocketPal.GetPlatformSocketFlags(m_SocketFlags);

            SocketError errorCode;
            if (m_Buffer != null)
            {
                errorCode = handle.AsyncContext.SendAsync(m_Buffer, m_Offset, m_Count, platformFlags, TransferCompletionCallback);
            }
            else
            {
                errorCode = handle.AsyncContext.SendAsync(new BufferList(m_BufferList), platformFlags, TransferCompletionCallback);
            }

            bytesTransferred = 0;
            return errorCode;
        }

        private void InnerStartOperationSendPackets()
        {
            throw new PlatformNotSupportedException();
        }

        internal SocketError DoOperationSendPackets(Socket socket, SafeCloseSocket handle)
        {
            throw new PlatformNotSupportedException();
        }

        private void InnerStartOperationSendTo()
        {
            _receivedFlags = System.Net.Sockets.SocketFlags.None;
            _socketAddressSize = 0;
        }

        internal SocketError DoOperationSendTo(SafeCloseSocket handle, out int bytesTransferred)
        {
            int platformFlags = SocketPal.GetPlatformSocketFlags(m_SocketFlags);

            SocketError errorCode;
            if (m_Buffer != null)
            {
                errorCode = handle.AsyncContext.SendToAsync(m_Buffer, m_Offset, m_Count, platformFlags, m_SocketAddress.Buffer, m_SocketAddress.Size, TransferCompletionCallback);
            }
            else
            {
                errorCode = handle.AsyncContext.SendToAsync(new BufferList(m_BufferList), platformFlags, m_SocketAddress.Buffer, m_SocketAddress.Size, TransferCompletionCallback);
            }

            bytesTransferred = 0;
            return errorCode;
        }

        internal void LogBuffer(int size)
        {
            // TODO: implement?
        }

        internal void LogSendPacketsBuffers(int size)
        {
            throw new PlatformNotSupportedException();
        }

        private SocketError FinishOperationAccept(Internals.SocketAddress remoteSocketAddress)
        {
            System.Buffer.BlockCopy(m_AcceptBuffer, 0, remoteSocketAddress.Buffer, 0, m_AcceptAddressBufferCount);
            m_AcceptSocket = _currentSocket.CreateAcceptSocket(
                SafeCloseSocket.CreateSocket(_acceptedFileDescriptor),
                _currentSocket.m_RightEndPoint.Create(remoteSocketAddress));
            return SocketError.Success;
        }

        private SocketError FinishOperationConnect()
        {
            // No-op for *nix.
            return SocketError.Success;
        }

        private unsafe int GetSocketAddressSize()
        {
            return _socketAddressSize;
        }

        private unsafe void FinishOperationReceiveMessageFrom()
        {
            // No-op for *nix.
        }

        private void FinishOperationSendPackets()
        {
            throw new PlatformNotSupportedException();
        }

        private void CompletionCallback(int bytesTransferred, SocketError socketError)
        {
            // TODO: plumb SocketFlags through TransferOperation
            if (socketError == SocketError.Success)
            {
                FinishOperationSuccess(socketError, bytesTransferred, _receivedFlags);
            }
            else
            {
                if (_currentSocket.CleanedUp)
                {
                    socketError = SocketError.OperationAborted;
                }

                FinishOperationAsyncFailure(socketError, bytesTransferred, _receivedFlags);
            }
        }
    }
}
