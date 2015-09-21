// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;
using Microsoft.Win32;
using System.Collections.Generic;

namespace System.Net.Sockets
{
    //
    //  OverlappedAsyncResult - used to take care of storage for async Socket operation
    //   from the BeginSend, BeginSendTo, BeginReceive, BeginReceiveFrom calls.
    //
    unsafe internal partial class ReceiveMessageOverlappedAsyncResult : BaseOverlappedAsyncResult
    {
        //
        // internal class members
        //
        private Interop.Winsock.WSAMsg* _message;
        private WSABuffer* _WSABuffer;
        private byte[] _WSABufferArray;
        private byte[] _controlBuffer;
        internal byte[] m_MessageBuffer;

        private static readonly int s_ControlDataSize = Marshal.SizeOf<Interop.Winsock.ControlData>();
        private static readonly int s_ControlDataIPv6Size = Marshal.SizeOf<Interop.Winsock.ControlDataIPv6>();
        private static readonly int s_WSABufferSize = Marshal.SizeOf<WSABuffer>();
        private static readonly int s_WSAMsgSize = Marshal.SizeOf<Interop.Winsock.WSAMsg>();

        private IntPtr GetSocketAddressSizePtr()
        {
            return Marshal.UnsafeAddrOfPinnedArrayElement(_socketAddress.Buffer, _socketAddress.GetAddressSizeOffset());
        }

        internal unsafe int GetSocketAddressSize()
        {
            return *(int*)GetSocketAddressSizePtr();
        }

        //
        // SetUnmanagedStructures -
        // Fills in Overlapped Structures used in an Async Overlapped Winsock call
        //   these calls are outside the runtime and are unmanaged code, so we need
        //   to prepare specific structures and ints that lie in unmanaged memory
        //   since the Overlapped calls can be Async
        //

        internal void SetUnmanagedStructures(byte[] buffer, int offset, int size, Internals.SocketAddress socketAddress, SocketFlags socketFlags)
        {
            m_MessageBuffer = new byte[s_WSAMsgSize];
            _WSABufferArray = new byte[s_WSABufferSize];

            bool ipv4, ipv6;
            Socket.GetIPProtocolInformation(((Socket)AsyncObject).AddressFamily, socketAddress, out ipv4, out ipv6);

            //prepare control buffer
            if (ipv4)
            {
                _controlBuffer = new byte[s_ControlDataSize];
            }
            else if (ipv6)
            {
                _controlBuffer = new byte[s_ControlDataIPv6Size];
            }

            //pin buffers
            object[] objectsToPin = new object[(_controlBuffer != null) ? 5 : 4];
            objectsToPin[0] = buffer;
            objectsToPin[1] = m_MessageBuffer;
            objectsToPin[2] = _WSABufferArray;

            //prepare socketaddress buffer
            _socketAddress = socketAddress;
            _socketAddress.CopyAddressSizeIntoBuffer();
            objectsToPin[3] = _socketAddress.Buffer;

            if (_controlBuffer != null)
            {
                objectsToPin[4] = _controlBuffer;
            }

            base.SetUnmanagedStructures(objectsToPin);

            //prepare data buffer
            _WSABuffer = (WSABuffer*)Marshal.UnsafeAddrOfPinnedArrayElement(_WSABufferArray, 0);
            _WSABuffer->Length = size;
            _WSABuffer->Pointer = Marshal.UnsafeAddrOfPinnedArrayElement(buffer, offset);


            //setup structure
            _message = (Interop.Winsock.WSAMsg*)Marshal.UnsafeAddrOfPinnedArrayElement(m_MessageBuffer, 0);
            _message->socketAddress = Marshal.UnsafeAddrOfPinnedArrayElement(_socketAddress.Buffer, 0);
            _message->addressLength = (uint)_socketAddress.Size;
            _message->buffers = Marshal.UnsafeAddrOfPinnedArrayElement(_WSABufferArray, 0);
            _message->count = 1;

            if (_controlBuffer != null)
            {
                _message->controlBuffer.Pointer = Marshal.UnsafeAddrOfPinnedArrayElement(_controlBuffer, 0);
                _message->controlBuffer.Length = _controlBuffer.Length;
            }

            _message->flags = socketFlags;
        }

        unsafe private void InitIPPacketInformation()
        {
            IPAddress address = null;

            //ipv4
            if (_controlBuffer.Length == s_ControlDataSize)
            {
                Interop.Winsock.ControlData controlData = Marshal.PtrToStructure<Interop.Winsock.ControlData>(_message->controlBuffer.Pointer);
                if (controlData.length != UIntPtr.Zero)
                {
                    address = new IPAddress((long)controlData.address);
                }
                _ipPacketInformation = new IPPacketInformation(((address != null) ? address : IPAddress.None), (int)controlData.index);
            }
            //ipv6
            else if (_controlBuffer.Length == s_ControlDataIPv6Size)
            {
                Interop.Winsock.ControlDataIPv6 controlData = Marshal.PtrToStructure<Interop.Winsock.ControlDataIPv6>(_message->controlBuffer.Pointer);
                if (controlData.length != UIntPtr.Zero)
                {
                    address = new IPAddress(controlData.address);
                }
                _ipPacketInformation = new IPPacketInformation(((address != null) ? address : IPAddress.IPv6None), (int)controlData.index);
            }
            //other
            else
            {
                _ipPacketInformation = new IPPacketInformation();
            }
        }

        //
        // This method is called after an asynchronous call is made for the user,
        // it checks and acts accordingly if the IO:
        // 1) completed synchronously.
        // 2) was pended.
        // 3) failed.
        //

        internal void SyncReleaseUnmanagedStructures()
        {
            InitIPPacketInformation();
            ForceReleaseUnmanagedStructures();
        }

        protected override void ForceReleaseUnmanagedStructures()
        {
            _socketFlags = _message->flags;
            base.ForceReleaseUnmanagedStructures();
        }

        internal override object PostCompletion(int numBytes)
        {
            InitIPPacketInformation();
            if (ErrorCode == 0)
            {
                if (Logging.On) LogBuffer(numBytes);
            }
            return (int)numBytes;
        }

        private void LogBuffer(int size)
        {
            GlobalLog.Assert(Logging.On, "ReceiveMessageOverlappedAsyncResult#{0}::LogBuffer()|Logging is off!", Logging.HashString(this));
            Logging.Dump(Logging.Sockets, AsyncObject, "PostCompletion", _WSABuffer->Pointer, Math.Min(_WSABuffer->Length, size));
        }
    }; // class OverlappedAsyncResult
} // namespace System.Net.Sockets