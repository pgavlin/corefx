// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Collections;
using System.Collections.Generic;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using System.Diagnostics;
using System.Diagnostics.Contracts;
using System.Threading.Tasks;

namespace System.Net.Sockets
{
    internal static class SocketPal
    {
        private static void MicrosecondsToTimeValue(long microseconds, ref Interop.Winsock.TimeValue socketTime)
        {
            const int microcnv = 1000000;

            socketTime.Seconds = (int)(microseconds / microcnv);
            socketTime.Microseconds = (int)(microseconds % microcnv);
        }

        public static SocketError GetLastSocketError()
        {
            return (SocketError)Marshal.GetLastWin32Error();
        }

        public static SafeCloseSocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
        {
            SafeCloseSocket handle = SafeCloseSocket.CreateWSASocket(addressFamily, socketType, protocolType);
            if (handle.IsInvalid)
            {
                //
                // failed to create the win32 socket, throw
                //
                throw new SocketException();
            }
            return handle;
        }

        public static unsafe SafeCloseSocket CreateSocket(SocketInformation socketInformation, out AddressFamily addressFamily, out SocketType socketType, out ProtocolType protocolType)
        {
            SafeCloseSocket handle;
            Interop.Winsock.WSAPROTOCOL_INFO protocolInfo;

            fixed (byte* pinnedBuffer = socketInformation.ProtocolInformation)
            {
                handle = SafeCloseSocket.CreateWSASocket(pinnedBuffer);
                protocolInfo = (Interop.Winsock.WSAPROTOCOL_INFO)Marshal.PtrToStructure<Interop.Winsock.WSAPROTOCOL_INFO>((IntPtr)pinnedBuffer);
            }

            if (handle.IsInvalid)
            {
                SocketException e = new SocketException();
                if (e.SocketErrorCode == SocketError.InvalidArgument)
                {
                    throw new ArgumentException(SR.net_sockets_invalid_socketinformation, "socketInformation");
                }
                else
                {
                    throw e;
                }
            }

            addressFamily = protocolInfo.iAddressFamily;
            socketType = (SocketType)protocolInfo.iSocketType;
            protocolType = (ProtocolType)protocolInfo.iProtocol;
            return handle;
        }

        public static SocketError SetBlocking(SafeCloseSocket handle, bool shouldBlock, out bool willBlock)
        {
            int intBlocking = shouldBlock ? 0 : -1;

            SocketError errorCode;
            errorCode = Interop.Winsock.ioctlsocket(
                handle,
                Interop.Winsock.IoctlSocketConstants.FIONBIO,
                ref intBlocking);

            if (errorCode == SocketError.SocketError)
            {
                errorCode = (SocketError)Marshal.GetLastWin32Error();
            }

            willBlock = intBlocking == 0;
            return errorCode;
        }

        public static SocketError GetSockName(SafeCloseSocket handle, byte[] buffer, ref int nameLen)
        {
            return Interop.Winsock.getsockname(handle, buffer, ref nameLen);
        }

        public static SocketError GetAvailable(SafeCloseSocket handle, out int available)
        {
            int value = 0;
            SocketError errorCode = Interop.Winsock.ioctlsocket(
                handle,
                Interop.Winsock.IoctlSocketConstants.FIONREAD,
                ref value);
            available = value;
            return errorCode;
        }

        public static SocketError GetPeerName(SafeCloseSocket handle, byte[] buffer, ref int nameLen)
        {
            return Interop.Winsock.getpeername(handle, buffer, ref nameLen);
        }

        public static SocketError Bind(SafeCloseSocket handle, byte[] buffer, int nameLen)
        {
            return Interop.Winsock.bind(handle, buffer, nameLen);
        }

        public static SocketError Listen(SafeCloseSocket handle, int backlog)
        {
            return Interop.Winsock.listen(handle, backlog);
        }

        public static SafeCloseSocket Accept(SafeCloseSocket handle, byte[] buffer, ref int nameLen)
        {
            return SafeCloseSocket.Accept(handle, buffer, ref nameLen);
        }

        public static SocketError Connect(SafeCloseSocket handle, byte[] peerAddress, int peerAddressLen)
        {
            return Interop.Winsock.WSAConnect(
                handle.DangerousGetHandle(),
                peerAddress,
                peerAddressLen,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero,
                IntPtr.Zero);
        }

        public static SocketError Send(SafeCloseSocket handle, BufferOffsetSize[] buffers, SocketFlags socketFlags, out int bytesTransferred)
        {
            WSABuffer[] WSABuffers = new WSABuffer[buffers.Length];
            GCHandle[] objectsToPin = null;

            try
            {
                objectsToPin = new GCHandle[buffers.Length];
                for (int i = 0; i < buffers.Length; ++i)
                {
                    objectsToPin[i] = GCHandle.Alloc(buffers[i].Buffer, GCHandleType.Pinned);
                    WSABuffers[i].Length = buffers[i].Size;
                    WSABuffers[i].Pointer = Marshal.UnsafeAddrOfPinnedArrayElement(buffers[i].Buffer, buffers[i].Offset);
                }

                // This can throw ObjectDisposedException.
                return Interop.Winsock.WSASend_Blocking(
                    handle.DangerousGetHandle(),
                    WSABuffers,
                    WSABuffers.Length,
                    out bytesTransferred,
                    socketFlags,
                    SafeNativeOverlapped.Zero,
                    IntPtr.Zero);
            }
            finally
            {
                if (objectsToPin != null)
                    for (int i = 0; i < objectsToPin.Length; ++i)
                        if (objectsToPin[i].IsAllocated)
                            objectsToPin[i].Free();
            }
        }

        public static SocketError Send(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, out int bytesTransferred)
        {
            int count = buffers.Count;
            WSABuffer[] WSABuffers = new WSABuffer[count];
            GCHandle[] objectsToPin = null;

            try
            {
                objectsToPin = new GCHandle[count];
                for (int i = 0; i < count; ++i)
                {
                    ArraySegment<byte> buffer = buffers[i];
                    RangeValidationHelpers.ValidateSegment(buffer);
                    objectsToPin[i] = GCHandle.Alloc(buffer.Array, GCHandleType.Pinned);
                    WSABuffers[i].Length = buffer.Count;
                    WSABuffers[i].Pointer = Marshal.UnsafeAddrOfPinnedArrayElement(buffer.Array, buffer.Offset);
                }

                // This may throw ObjectDisposedException.
                SocketError errorCode = Interop.Winsock.WSASend_Blocking(
                    handle.DangerousGetHandle(),
                    WSABuffers,
                    count,
                    out bytesTransferred,
                    socketFlags,
                    SafeNativeOverlapped.Zero,
                    IntPtr.Zero);

                if ((SocketError)errorCode == SocketError.SocketError)
                {
                    errorCode = (SocketError)Marshal.GetLastWin32Error();
                }

                return errorCode;
            }
            finally
            {
                if (objectsToPin != null)
                    for (int i = 0; i < objectsToPin.Length; ++i)
                        if (objectsToPin[i].IsAllocated)
                            objectsToPin[i].Free();
            }
        }

        public static unsafe int Send(SafeCloseSocket handle, byte[] buffer, int offset, int size, SocketFlags socketFlags)
        {
            if (buffer.Length == 0)
                return Interop.Winsock.send(handle.DangerousGetHandle(), null, 0, socketFlags);
            else
            {
                fixed (byte* pinnedBuffer = buffer)
                {
                    return Interop.Winsock.send(
                        handle.DangerousGetHandle(),
                        pinnedBuffer + offset,
                        size,
                        socketFlags);
                }
            }
        }

        public static unsafe int SendTo(SafeCloseSocket handle, byte[] buffer, int offset, int size, SocketFlags socketFlags, byte[] peerAddress, int peerAddressSize)
        {
            if (buffer.Length == 0)
            {
                return Interop.Winsock.sendto(
                    handle.DangerousGetHandle(),
                    null,
                    0,
                    socketFlags,
                    peerAddress,
                    peerAddressSize);
            }
            else
            {
                fixed (byte* pinnedBuffer = buffer)
                {
                    return Interop.Winsock.sendto(
                        handle.DangerousGetHandle(),
                        pinnedBuffer + offset,
                        size,
                        socketFlags,
                        peerAddress,
                        peerAddressSize);
                }
            }
        }

        public static SocketError Receive(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, ref SocketFlags socketFlags, out int bytesTransferred)
        {
            int count = buffers.Count;
            WSABuffer[] WSABuffers = new WSABuffer[count];
            GCHandle[] objectsToPin = null;

            try
            {
                objectsToPin = new GCHandle[count];
                for (int i = 0; i < count; ++i)
                {
                    ArraySegment<byte> buffer = buffers[i];
                    RangeValidationHelpers.ValidateSegment(buffer);
                    objectsToPin[i] = GCHandle.Alloc(buffer.Array, GCHandleType.Pinned);
                    WSABuffers[i].Length = buffer.Count;
                    WSABuffers[i].Pointer = Marshal.UnsafeAddrOfPinnedArrayElement(buffer.Array, buffer.Offset);
                }

                // This can throw ObjectDisposedException.
                SocketError errorCode = Interop.Winsock.WSARecv_Blocking(
                    handle.DangerousGetHandle(),
                    WSABuffers,
                    count,
                    out bytesTransferred,
                    ref socketFlags,
                    SafeNativeOverlapped.Zero,
                    IntPtr.Zero);

                if ((SocketError)errorCode == SocketError.SocketError)
                {
                    errorCode = (SocketError)Marshal.GetLastWin32Error();
                }

                return errorCode;
            }
            finally
            {
                if (objectsToPin != null)
                    for (int i = 0; i < objectsToPin.Length; ++i)
                        if (objectsToPin[i].IsAllocated)
                            objectsToPin[i].Free();
            }
        }

        public static unsafe int Receive(SafeCloseSocket handle, byte[] buffer, int offset, int size, SocketFlags socketFlags)
        {
            if (buffer.Length == 0)
            {
                return Interop.Winsock.recv(handle.DangerousGetHandle(), null, 0, socketFlags);
            }
            else
                fixed (byte* pinnedBuffer = buffer)
                {
                    return Interop.Winsock.recv(handle.DangerousGetHandle(), pinnedBuffer + offset, size, socketFlags);
                }
        }

        public static SocketError ReceiveMessageFrom(Socket socket, SafeCloseSocket handle, byte[] buffer, int offset, int size, ref SocketFlags socketFlags, Internals.SocketAddress socketAddress, out Internals.SocketAddress receiveAddress, out IPPacketInformation ipPacketInformation, out int bytesTransferred)
        {
            ReceiveMessageOverlappedAsyncResult asyncResult = new ReceiveMessageOverlappedAsyncResult(socket, null, null);
            asyncResult.SetUnmanagedStructures(buffer, offset, size, socketAddress, socketFlags);

            SocketError errorCode = SocketError.Success;

            bytesTransferred = 0;
            try
            {
                // This can throw ObjectDisposedException (retrieving the delegate AND resolving the handle).
                if (socket.WSARecvMsg_Blocking(
                    handle.DangerousGetHandle(),
                    Marshal.UnsafeAddrOfPinnedArrayElement(asyncResult.m_MessageBuffer, 0),
                    out bytesTransferred,
                    IntPtr.Zero,
                    IntPtr.Zero) == SocketError.SocketError)
                {
                    errorCode = (SocketError)Marshal.GetLastWin32Error();
                }
            }
            finally
            {
                asyncResult.SyncReleaseUnmanagedStructures();
            }

            socketFlags = asyncResult.m_flags;
            receiveAddress = asyncResult.m_SocketAddress;
            ipPacketInformation = asyncResult.m_IPPacketInformation;

            return errorCode;
        }

        public static unsafe int ReceiveFrom(SafeCloseSocket handle, byte[] buffer, int offset, int size, SocketFlags socketFlags, byte[] socketAddress, ref int addressLength)
        {
            if (buffer.Length == 0)
                return Interop.Winsock.recvfrom(handle.DangerousGetHandle(), null, 0, socketFlags, socketAddress, ref addressLength);
            else
                fixed (byte* pinnedBuffer = buffer)
                {
                    return Interop.Winsock.recvfrom(handle.DangerousGetHandle(), pinnedBuffer + offset, size, socketFlags, socketAddress, ref addressLength);
                }
        }

        public static SocketError Ioctl(SafeCloseSocket handle, int ioControlCode, byte[] optionInValue, byte[] optionOutValue, out int optionLength)
        {
            return Interop.Winsock.WSAIoctl_Blocking(
                handle.DangerousGetHandle(),
                ioControlCode,
                optionInValue,
                optionInValue != null ? optionInValue.Length : 0,
                optionOutValue,
                optionOutValue != null ? optionOutValue.Length : 0,
                out optionLength,
                SafeNativeOverlapped.Zero,
                IntPtr.Zero);
        }

        public static SocketError IoctlInternal(SafeCloseSocket handle, IOControlCode ioControlCode, IntPtr optionInValue, int inValueLength, IntPtr optionOutValue, int outValueLength, out int optionLength)
        {
            return Interop.Winsock.WSAIoctl_Blocking_Internal(
                handle.DangerousGetHandle(),
                (uint)ioControlCode,
                optionInValue,
                inValueLength,
                optionOutValue,
                outValueLength,
                out optionLength,
                SafeNativeOverlapped.Zero,
                IntPtr.Zero);
        }

        public static unsafe SocketError SetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, int optionValue)
        {
            return Interop.Winsock.setsockopt(
                handle,
                optionLevel,
                optionName,
                ref optionValue,
                sizeof(int));
        }

        public static SocketError SetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue)
        {
            return Interop.Winsock.setsockopt(
                handle,
                optionLevel,
                optionName,
                optionValue,
                optionValue != null ? optionValue.Length : 0);
        }

        public static SocketError GetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, out int optionValue)
        {
            int optionLength = 4; // sizeof(int)
            return Interop.Winsock.getsockopt(
                handle,
                optionLevel,
                optionName,
                out optionValue,
                ref optionLength);
        }

        public static SocketError GetSockOpt(SafeCloseSocket handle, SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue, ref int optionLength)
        {
             return Interop.Winsock.getsockopt(
                handle,
                optionLevel,
                optionName,
                optionValue,
                ref optionLength);
        }

        public static SocketError Poll(SafeCloseSocket handle, int microseconds, SelectMode mode, out bool status)
        {
            IntPtr rawHandle = handle.DangerousGetHandle();
            IntPtr[] fileDescriptorSet = new IntPtr[2] { (IntPtr)1, rawHandle };
            Interop.Winsock.TimeValue IOwait = new Interop.Winsock.TimeValue();

            //
            // negative timeout value implies indefinite wait
            //
            int socketCount;
            if (microseconds != -1)
            {
                MicrosecondsToTimeValue((long)(uint)microseconds, ref IOwait);
                socketCount =
                    Interop.Winsock.select(
                        0,
                        mode == SelectMode.SelectRead ? fileDescriptorSet : null,
                        mode == SelectMode.SelectWrite ? fileDescriptorSet : null,
                        mode == SelectMode.SelectError ? fileDescriptorSet : null,
                        ref IOwait);
            }
            else
            {
                socketCount =
                    Interop.Winsock.select(
                        0,
                        mode == SelectMode.SelectRead ? fileDescriptorSet : null,
                        mode == SelectMode.SelectWrite ? fileDescriptorSet : null,
                        mode == SelectMode.SelectError ? fileDescriptorSet : null,
                        IntPtr.Zero);
            }

            if ((SocketError)socketCount == SocketError.SocketError)
            {
                status = false;
                return SocketError.SocketError;
            }

            status = (int)fileDescriptorSet[0] != 0 && fileDescriptorSet[1] == rawHandle;
            return (SocketError)socketCount;
        }

        public static SocketError Select(IList checkRead, IList checkWrite, IList checkError, int microseconds)
        {
            IntPtr[] readfileDescriptorSet = Socket.SocketListToFileDescriptorSet(checkRead);
            IntPtr[] writefileDescriptorSet = Socket.SocketListToFileDescriptorSet(checkWrite);
            IntPtr[] errfileDescriptorSet = Socket.SocketListToFileDescriptorSet(checkError);

            // This code used to erroneously pass a non-null timeval structure containing zeroes 
            // to select() when the caller specified (-1) for the microseconds parameter.  That 
            // caused select to actually have a *zero* timeout instead of an infinite timeout
            // turning the operation into a non-blocking poll.
            //
            // Now we pass a null timeval struct when microseconds is (-1).
            // 
            // Negative microsecond values that weren't exactly (-1) were originally successfully 
            // converted to a timeval struct containing unsigned non-zero integers.  This code 
            // retains that behavior so that any app working around the original bug with, 
            // for example, (-2) specified for microseconds, will continue to get the same behavior.

            int socketCount;
            if (microseconds != -1)
            {
                Interop.Winsock.TimeValue IOwait = new Interop.Winsock.TimeValue();
                MicrosecondsToTimeValue((long)(uint)microseconds, ref IOwait);

                socketCount =
                    Interop.Winsock.select(
                        0, // ignored value
                        readfileDescriptorSet,
                        writefileDescriptorSet,
                        errfileDescriptorSet,
                        ref IOwait);
            }
            else
            {
                socketCount =
                    Interop.Winsock.select(
                        0, // ignored value
                        readfileDescriptorSet,
                        writefileDescriptorSet,
                        errfileDescriptorSet,
                        IntPtr.Zero);
            }

            GlobalLog.Print("Socket::Select() Interop.Winsock.select returns socketCount:" + socketCount);

            if ((SocketError)socketCount == SocketError.SocketError)
            {
                return SocketError.SocketError;
            }

            Socket.SelectFileDescriptor(checkRead, readfileDescriptorSet);
            Socket.SelectFileDescriptor(checkWrite, writefileDescriptorSet);
            Socket.SelectFileDescriptor(checkError, errfileDescriptorSet);

            return (SocketError)socketCount;
        }

        public static SocketError Shutdown(SafeCloseSocket handle, SocketShutdown how)
        {
            SocketError err = Interop.Winsock.shutdown(handle, (int)how);
            return err == SocketError.SocketError ? GetLastSocketError() : SocketError.Success;
        }

        public static unsafe SocketError ConnectAsync(Socket socket, SafeCloseSocket handle, byte[] socketAddress, int socketAddressLen, ConnectOverlappedAsyncResult asyncResult)
        {
            // This will pin socketAddress buffer
            asyncResult.SetUnmanagedStructures(socketAddress);

            int ignoreBytesSent;
            if (!socket.ConnectEx(
                handle,
                Marshal.UnsafeAddrOfPinnedArrayElement(socketAddress, 0), 
                socketAddressLen,
                IntPtr.Zero,
                0,
                out ignoreBytesSent,
                asyncResult.OverlappedHandle))
            {
                return GetLastSocketError();
            }

            return SocketError.Success;
        }

        public static unsafe SocketError SendAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // Set up asyncResult for overlapped WSASend.
            // This call will use completion ports.
            asyncResult.SetUnmanagedStructures(buffer, offset, count, null, false /*don't pin null remoteEP*/);

            // This can throw ObjectDisposedException.
            int bytesTransferred;
            SocketError errorCode = Interop.Winsock.WSASend(
                handle,
                ref asyncResult.m_SingleBuffer,
                1, // only ever 1 buffer being sent
                out bytesTransferred,
                socketFlags,
                asyncResult.OverlappedHandle,
                IntPtr.Zero);

            if (errorCode != SocketError.Success)
            {
                errorCode = GetLastSocketError();
            }

            return errorCode;
        }

        public static unsafe SocketError SendAsync(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // Set up asyncResult for overlapped WSASend.
            // This call will use completion ports.
            asyncResult.SetUnmanagedStructures(buffers);

            // This can throw ObjectDisposedException.
            int bytesTransferred;
            SocketError errorCode = Interop.Winsock.WSASend(
                handle,
                asyncResult.m_WSABuffers,
                asyncResult.m_WSABuffers.Length,
                out bytesTransferred,
                socketFlags,
                asyncResult.OverlappedHandle,
                IntPtr.Zero);

            if (errorCode != SocketError.Success)
            {
                errorCode = GetLastSocketError();
            }

            return errorCode;
        }

        public static unsafe SocketError SendAsync(SafeCloseSocket handle, BufferOffsetSize[] buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // Set up asyncResult for overlapped WSASend.
            // This call will use completion ports.
            asyncResult.SetUnmanagedStructures(buffers);

            // This can throw ObjectDisposedException.
            int bytesTransferred;
            SocketError errorCode = Interop.Winsock.WSASend(
                handle,
                asyncResult.m_WSABuffers,
                asyncResult.m_WSABuffers.Length,
                out bytesTransferred,
                socketFlags,
                asyncResult.OverlappedHandle,
                IntPtr.Zero);

            if (errorCode != SocketError.Success)
            {
                errorCode = GetLastSocketError();
            }

            return errorCode;
        }

        public static unsafe SocketError SendToAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, Internals.SocketAddress socketAddress, OverlappedAsyncResult asyncResult)
        {
            // Set up asyncResult for overlapped WSASendTo.
            // This call will use completion ports.
            asyncResult.SetUnmanagedStructures(buffer, offset, count, socketAddress, false /* don't pin RemoteEP*/);

            int bytesTransferred;
            SocketError errorCode = Interop.Winsock.WSASendTo(
                handle,
                ref asyncResult.m_SingleBuffer,
                1, // only ever 1 buffer being sent
                out bytesTransferred,
                socketFlags,
                asyncResult.GetSocketAddressPtr(),
                asyncResult.SocketAddress.Size,
                asyncResult.OverlappedHandle,
                IntPtr.Zero);

            if (errorCode != SocketError.Success)
            {
                errorCode = SocketPal.GetLastSocketError();
            }

            return errorCode;
        }

        public static unsafe SocketError ReceiveAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // Set up asyncResult for overlapped WSARecv.
            // This call will use completion ports.
            asyncResult.SetUnmanagedStructures(buffer, offset, count, null, false /* don't pin null RemoteEP*/);

            // This can throw ObjectDisposedException.
            int bytesTransferred;
            SocketError errorCode = Interop.Winsock.WSARecv(
                handle,
                ref asyncResult.m_SingleBuffer,
                1,
                out bytesTransferred,
                ref socketFlags,
                asyncResult.OverlappedHandle,
                IntPtr.Zero);

            if (errorCode != SocketError.Success)
            {
                errorCode = GetLastSocketError();
            }

            return errorCode;
        }

        public static unsafe SocketError ReceiveAsync(SafeCloseSocket handle, IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            // Set up asyncResult for overlapped WSASend.
            // This call will use completion ports.
            asyncResult.SetUnmanagedStructures(buffers);

            // This can throw ObjectDisposedException.
            int bytesTransferred;
            SocketError errorCode = Interop.Winsock.WSARecv(
                handle,
                asyncResult.m_WSABuffers,
                asyncResult.m_WSABuffers.Length,
                out bytesTransferred,
                ref socketFlags,
                asyncResult.OverlappedHandle,
                IntPtr.Zero);

            if (errorCode != SocketError.Success)
            {
                errorCode = GetLastSocketError();
            }

            return errorCode;
        }

        public static unsafe SocketError ReceiveFromAsync(SafeCloseSocket handle, byte[] buffer, int offset, int count, SocketFlags socketFlags, Internals.SocketAddress socketAddress, OverlappedAsyncResult asyncResult)
        {
            // Set up asyncResult for overlapped WSARecvFrom.
            // This call will use completion ports on WinNT and Overlapped IO on Win9x.
            asyncResult.SetUnmanagedStructures(buffer, offset, count, socketAddress, true /* pin remoteEP*/);

            int bytesTransferred;
            SocketError errorCode = Interop.Winsock.WSARecvFrom(
                handle,
                ref asyncResult.m_SingleBuffer,
                1,
                out bytesTransferred,
                ref socketFlags,
                asyncResult.GetSocketAddressPtr(),
                asyncResult.GetSocketAddressSizePtr(),
                asyncResult.OverlappedHandle,
                IntPtr.Zero);

            if (errorCode != SocketError.Success)
            {
                errorCode = SocketPal.GetLastSocketError();
            }

            return errorCode;
        }

        public static unsafe SocketError AcceptAsync(Socket socket, SafeCloseSocket handle, SafeCloseSocket acceptHandle, int receiveSize, int socketAddressSize, AcceptOverlappedAsyncResult asyncResult)
        {
            //the buffer needs to contain the requested data plus room for two sockaddrs and 16 bytes
            //of associated data for each.
            int addressBufferSize = socketAddressSize + 16;
            byte[] buffer = new byte[receiveSize + ((addressBufferSize) * 2)];

            //
            // Set up asyncResult for overlapped AcceptEx.
            // This call will use
            // completion ports on WinNT
            //

            asyncResult.SetUnmanagedStructures(buffer, addressBufferSize);

            // This can throw ObjectDisposedException.
            int bytesTransferred;
            SocketError errorCode = SocketError.Success;
            if (!socket.AcceptEx(
                handle,
                acceptHandle,
                Marshal.UnsafeAddrOfPinnedArrayElement(asyncResult.Buffer, 0),
                receiveSize,
                addressBufferSize,
                addressBufferSize,
                out bytesTransferred,
                asyncResult.OverlappedHandle))
            {
                errorCode = SocketPal.GetLastSocketError();
            }

            return errorCode;
        }
    }
}
