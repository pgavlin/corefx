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
    public partial class SocketAsyncEventArgs : EventArgs, IDisposable
    {
        // Struct sizes needed for some custom marshalling.
        internal static readonly int s_ControlDataSize = Marshal.SizeOf<Interop.Winsock.ControlData>();
        internal static readonly int s_ControlDataIPv6Size = Marshal.SizeOf<Interop.Winsock.ControlDataIPv6>();
        internal static readonly int s_WSAMsgSize = Marshal.SizeOf<Interop.Winsock.WSAMsg>();

        // Buffer,Offset,Count property variables.
        internal WSABuffer m_WSABuffer;
        internal IntPtr m_PtrSingleBuffer;

        // BufferList property variables.
        internal WSABuffer[] m_WSABufferArray;

        // Internal buffers for WSARecvMsg
        private byte[] _WSAMessageBuffer;
        private GCHandle _WSAMessageBufferGCHandle;
        internal IntPtr m_PtrWSAMessageBuffer;
        private byte[] _controlBuffer;
        private GCHandle _controlBufferGCHandle;
        internal IntPtr m_PtrControlBuffer;
        private WSABuffer[] _WSARecvMsgWSABufferArray;
        private GCHandle _WSARecvMsgWSABufferArrayGCHandle;
        private IntPtr _ptrWSARecvMsgWSABufferArray;

        // Internal buffer for AcceptEx when Buffer not supplied.
        internal IntPtr m_PtrAcceptBuffer;

        // Internal SocketAddress buffer
        private GCHandle _socketAddressGCHandle;
        private Internals.SocketAddress _pinnedSocketAddress;
        internal IntPtr m_PtrSocketAddressBuffer;
        internal IntPtr m_PtrSocketAddressBufferSize;

        // Internal variables for SendPackets
        internal FileStream[] m_SendPacketsFileStreams;
        internal SafeHandle[] m_SendPacketsFileHandles;
        internal Interop.Winsock.TransmitPacketsElement[] m_SendPacketsDescriptor;
        internal IntPtr m_PtrSendPacketsDescriptor;

        // Overlapped object related variables.
        internal SafeNativeOverlapped m_PtrNativeOverlapped;
        private PreAllocatedOverlapped _preAllocatedOverlapped;
        private object[] _objectsToPin;
        private enum PinState
        {
            None = 0,
            NoBuffer,
            SingleAcceptBuffer,
            SingleBuffer,
            MultipleBuffer,
            SendPackets
        }
        private PinState _pinState;
        private byte[] _pinnedAcceptBuffer;
        private byte[] _pinnedSingleBuffer;
        private int _pinnedSingleBufferOffset;
        private int _pinnedSingleBufferCount;

        private void InitializeInternals()
        {
            // Zero tells TransmitPackets to select a default send size.
            m_SendPacketsSendSize = 0;
        }
        private void FreeInternals(bool calledFromFinalizer)
        {
            // Free native overlapped data.
            FreeOverlapped(calledFromFinalizer);
        }

        private void InnerComplete()
        {
            CompleteIOCPOperation();
        }

        internal unsafe void PrepareIOCPOperation()
        {
            Debug.Assert(_currentSocket != null, "m_CurrentSocket is null");
            Debug.Assert(_currentSocket.SafeHandle != null, "m_CurrentSocket.SafeHandle is null");
            Debug.Assert(!_currentSocket.SafeHandle.IsInvalid, "m_CurrentSocket.SafeHandle is invalid");

            ThreadPoolBoundHandle boundHandle = _currentSocket.SafeHandle.GetOrAllocateThreadPoolBoundHandle();

            NativeOverlapped* overlapped = null;
            if (_preAllocatedOverlapped != null)
            {
                overlapped = boundHandle.AllocateNativeOverlapped(_preAllocatedOverlapped);
                GlobalLog.Print(
                    "SocketAsyncEventArgs#" + Logging.HashString(this) +
                    "::boundHandle#" + Logging.HashString(boundHandle) +
                    "::AllocateNativeOverlapped(m_PreAllocatedOverlapped=" +
                    Logging.HashString(_preAllocatedOverlapped) +
                    "). Returned = " + ((IntPtr)overlapped).ToString("x"));
            }
            else
            {
                overlapped = boundHandle.AllocateNativeOverlapped(CompletionPortCallback, this, null);
                GlobalLog.Print(
                    "SocketAsyncEventArgs#" + Logging.HashString(this) +
                    "::boundHandle#" + Logging.HashString(boundHandle) +
                    "::AllocateNativeOverlapped(pinData=null)" +
                    "). Returned = " + ((IntPtr)overlapped).ToString("x"));
            }

            Debug.Assert(overlapped != null, "NativeOverlapped is null.");
            m_PtrNativeOverlapped = new SafeNativeOverlapped(_currentSocket.SafeHandle, overlapped);
        }

        internal void CompleteIOCPOperation()
        {
            // TODO: Optimization to remove callbacks if the operations are completed synchronously:
            //       Use SetFileCompletionNotificationModes(FILE_SKIP_COMPLETION_PORT_ON_SUCCESS).

            // If SetFileCompletionNotificationModes(FILE_SKIP_COMPLETION_PORT_ON_SUCCESS) is not set on this handle
            // it is guaranteed that the IOCP operation will be completed in the callback even if Socket.Success was 
            // returned by the Win32 API.

            // Required to allow another IOCP operation for the same handle.
            if (m_PtrNativeOverlapped != null)
            {
                m_PtrNativeOverlapped.Dispose();
                m_PtrNativeOverlapped = null;
            }
        }

        private void InnerStartOperationAccept(bool userSuppliedBuffer)
        {
            if (!userSuppliedBuffer)
            {
                CheckPinSingleBuffer(false);
            }
        }

        private void InnerStartOperationConnect()
        {
            // ConnectEx uses a sockaddr buffer containing he remote address to which to connect.
            // It can also optionally take a single buffer of data to send after the connection is complete.
            //
            // The sockaddr is pinned with a GCHandle to avoid having to use the object array form of UnsafePack.
            // The optional buffer is pinned using the Overlapped.UnsafePack method that takes a single object to pin.

            PinSocketAddressBuffer();
            CheckPinNoBuffer();
        }

        private void InnerStartOperationDisconnect()
        {
            CheckPinNoBuffer();
        }

        private void InnerStartOperationReceive()
        {
            // WWSARecv uses a WSABuffer array describing buffers of data to send.
            // Single and multiple buffers are handled differently so as to optimize
            // performance for the more common single buffer case.  
            // For a single buffer:
            //   The Overlapped.UnsafePack method is used that takes a single object to pin.
            //   A single WSABuffer that pre-exists in SocketAsyncEventArgs is used.
            // For multiple buffers:
            //   The Overlapped.UnsafePack method is used that takes an array of objects to pin.
            //   An array to reference the multiple buffer is allocated.
            //   An array of WSABuffer descriptors is allocated.
        }

        private void InnerStartOperationReceiveFrom()
        {
            // WSARecvFrom uses e a WSABuffer array describing buffers in which to 
            // receive data and from which to send data respectively. Single and multiple buffers
            // are handled differently so as to optimize performance for the more common single buffer case.
            // For a single buffer:
            //   The Overlapped.UnsafePack method is used that takes a single object to pin.
            //   A single WSABuffer that pre-exists in SocketAsyncEventArgs is used.
            // For multiple buffers:
            //   The Overlapped.UnsafePack method is used that takes an array of objects to pin.
            //   An array to reference the multiple buffer is allocated.
            //   An array of WSABuffer descriptors is allocated.
            // WSARecvFrom and WSASendTo also uses a sockaddr buffer in which to store the address from which the data was received.
            // The sockaddr is pinned with a GCHandle to avoid having to use the object array form of UnsafePack.
            PinSocketAddressBuffer();
        }

        private void InnerStartOperationReceiveMessageFrom()
        {
            // WSARecvMsg uses a WSAMsg descriptor.
            // The WSAMsg buffer is pinned with a GCHandle to avoid complicating the use of Overlapped.
            // WSAMsg contains a pointer to a sockaddr.  
            // The sockaddr is pinned with a GCHandle to avoid complicating the use of Overlapped.
            // WSAMsg contains a pointer to a WSABuffer array describing data buffers.
            // WSAMsg also contains a single WSABuffer describing a control buffer.
            // 
            PinSocketAddressBuffer();

            // Create and pin a WSAMessageBuffer if none already.
            if (_WSAMessageBuffer == null)
            {
                _WSAMessageBuffer = new byte[s_WSAMsgSize];
                _WSAMessageBufferGCHandle = GCHandle.Alloc(_WSAMessageBuffer, GCHandleType.Pinned);
                m_PtrWSAMessageBuffer = Marshal.UnsafeAddrOfPinnedArrayElement(_WSAMessageBuffer, 0);
            }

            // Create and pin an appropriately sized control buffer if none already
            IPAddress ipAddress = (m_SocketAddress.Family == AddressFamily.InterNetworkV6
                ? m_SocketAddress.GetIPAddress() : null);
            bool ipv4 = (_currentSocket.AddressFamily == AddressFamily.InterNetwork
                || (ipAddress != null && ipAddress.IsIPv4MappedToIPv6)); // DualMode
            bool ipv6 = _currentSocket.AddressFamily == AddressFamily.InterNetworkV6;

            if (ipv4 && (_controlBuffer == null || _controlBuffer.Length != s_ControlDataSize))
            {
                if (_controlBufferGCHandle.IsAllocated)
                {
                    _controlBufferGCHandle.Free();
                }
                _controlBuffer = new byte[s_ControlDataSize];
            }
            else if (ipv6 && (_controlBuffer == null || _controlBuffer.Length != s_ControlDataIPv6Size))
            {
                if (_controlBufferGCHandle.IsAllocated)
                {
                    _controlBufferGCHandle.Free();
                }
                _controlBuffer = new byte[s_ControlDataIPv6Size];
            }
            if (!_controlBufferGCHandle.IsAllocated)
            {
                _controlBufferGCHandle = GCHandle.Alloc(_controlBuffer, GCHandleType.Pinned);
                m_PtrControlBuffer = Marshal.UnsafeAddrOfPinnedArrayElement(_controlBuffer, 0);
            }

            // If single buffer we need a pinned 1 element WSABuffer.
            if (m_Buffer != null)
            {
                if (_WSARecvMsgWSABufferArray == null)
                {
                    _WSARecvMsgWSABufferArray = new WSABuffer[1];
                }
                _WSARecvMsgWSABufferArray[0].Pointer = m_PtrSingleBuffer;
                _WSARecvMsgWSABufferArray[0].Length = m_Count;
                _WSARecvMsgWSABufferArrayGCHandle = GCHandle.Alloc(_WSARecvMsgWSABufferArray, GCHandleType.Pinned);
                _ptrWSARecvMsgWSABufferArray = Marshal.UnsafeAddrOfPinnedArrayElement(_WSARecvMsgWSABufferArray, 0);
            }
            else
            {
                // just pin the multi-buffer WSABuffer
                _WSARecvMsgWSABufferArrayGCHandle = GCHandle.Alloc(m_WSABufferArray, GCHandleType.Pinned);
                _ptrWSARecvMsgWSABufferArray = Marshal.UnsafeAddrOfPinnedArrayElement(m_WSABufferArray, 0);
            }

            // Fill in WSAMessageBuffer
            unsafe
            {
                Interop.Winsock.WSAMsg* pMessage = (Interop.Winsock.WSAMsg*)m_PtrWSAMessageBuffer; ;
                pMessage->socketAddress = m_PtrSocketAddressBuffer;
                pMessage->addressLength = (uint)m_SocketAddress.Size;
                pMessage->buffers = _ptrWSARecvMsgWSABufferArray;
                if (m_Buffer != null)
                {
                    pMessage->count = (uint)1;
                }
                else
                {
                    pMessage->count = (uint)m_WSABufferArray.Length;
                }
                if (_controlBuffer != null)
                {
                    pMessage->controlBuffer.Pointer = m_PtrControlBuffer;
                    pMessage->controlBuffer.Length = _controlBuffer.Length;
                }
                pMessage->flags = m_SocketFlags;
            }
        }

        private void InnerStartOperationSend()
        {
            // WSASend uses a WSABuffer array describing buffers of data to send.
            // Single and multiple buffers are handled differently so as to optimize
            // performance for the more common single buffer case.  
            // For a single buffer:
            //   The Overlapped.UnsafePack method is used that takes a single object to pin.
            //   A single WSABuffer that pre-exists in SocketAsyncEventArgs is used.
            // For multiple buffers:
            //   The Overlapped.UnsafePack method is used that takes an array of objects to pin.
            //   An array to reference the multiple buffer is allocated.
            //   An array of WSABuffer descriptors is allocated.
        }

        private void InnerStartOperationSendPackets()
        {
            // Prevent mutithreaded manipulation of the list.
            if (m_SendPacketsElements != null)
            {
                _sendPacketsElementsInternal = (SendPacketsElement[])m_SendPacketsElements.Clone();
            }

            // TransmitPackets uses an array of TRANSMIT_PACKET_ELEMENT structs as
            // descriptors for buffers and files to be sent.  It also takes a send size
            // and some flags.  The TRANSMIT_PACKET_ELEMENT for a file contains a native file handle.
            // This function basically opens the files to get the file handles, pins down any buffers
            // specified and builds the native TRANSMIT_PACKET_ELEMENT array that will be passed
            // to TransmitPackets.

            // Scan the elements to count files and buffers
            m_SendPacketsElementsFileCount = 0;
            m_SendPacketsElementsBufferCount = 0;

            Debug.Assert(_sendPacketsElementsInternal != null);

            foreach (SendPacketsElement spe in _sendPacketsElementsInternal)
            {
                if (spe != null)
                {
                    if (spe.m_FilePath != null)
                    {
                        m_SendPacketsElementsFileCount++;
                    }
                    if (spe.m_Buffer != null && spe.m_Count > 0)
                    {
                        m_SendPacketsElementsBufferCount++;
                    }
                }
            }

            // Attempt to open the files if any
            if (m_SendPacketsElementsFileCount > 0)
            {
                // Create arrays for streams and handles
                m_SendPacketsFileStreams = new FileStream[m_SendPacketsElementsFileCount];
                m_SendPacketsFileHandles = new SafeHandle[m_SendPacketsElementsFileCount];

                // Loop through the elements attempting to open each files and get its handle
                int index = 0;
                foreach (SendPacketsElement spe in _sendPacketsElementsInternal)
                {
                    if (spe != null && spe.m_FilePath != null)
                    {
                        Exception fileStreamException = null;
                        try
                        {
                            // Create a FileStream to open the file
                            m_SendPacketsFileStreams[index] =
                                new FileStream(spe.m_FilePath, FileMode.Open, FileAccess.Read, FileShare.Read);
                        }
                        catch (Exception ex)
                        {
                            // Save the exception to throw after closing any previous successful file opens
                            fileStreamException = ex;
                        }
                        if (fileStreamException != null)
                        {
                            // Got exception opening a file - do some cleanup then throw
                            for (int i = 0; i < m_SendPacketsElementsFileCount; i++)
                            {
                                // Dereference handles
                                m_SendPacketsFileHandles[i] = null;
                                // Close any open streams
                                if (m_SendPacketsFileStreams[i] != null)
                                {
                                    m_SendPacketsFileStreams[i].Dispose();
                                    m_SendPacketsFileStreams[i] = null;
                                }
                            }
                            throw fileStreamException;
                        }

                        // Get the file handle from the stream
                        m_SendPacketsFileHandles[index] = m_SendPacketsFileStreams[index].SafeFileHandle;
                        index++;
                    }
                }
            }

            CheckPinSendPackets();
        }

        private void InnerStartOperationSendTo()
        {
            // WSASendTo uses a WSABuffer array describing buffers in which to 
            // receive data and from which to send data respectively. Single and multiple buffers
            // are handled differently so as to optimize performance for the more common single buffer case.
            // For a single buffer:
            //   The Overlapped.UnsafePack method is used that takes a single object to pin.
            //   A single WSABuffer that pre-exists in SocketAsyncEventArgs is used.
            // For multiple buffers:
            //   The Overlapped.UnsafePack method is used that takes an array of objects to pin.
            //   An array to reference the multiple buffer is allocated.
            //   An array of WSABuffer descriptors is allocated.
            // WSARecvFrom and WSASendTo also uses a sockaddr buffer in which to store the address from which the data was received.
            // The sockaddr is pinned with a GCHandle to avoid having to use the object array form of UnsafePack.
            PinSocketAddressBuffer();
        }

        // Method to ensure Overlapped object exists for operations that need no data buffer.
        private void CheckPinNoBuffer()
        {
            // PreAllocatedOverlapped will be reused.
            if (_pinState == PinState.None)
            {
                SetupOverlappedSingle(true);
            }
        }

        // Method to maintain pinned state of single buffer
        private void CheckPinSingleBuffer(bool pinUsersBuffer)
        {
            if (pinUsersBuffer)
            {
                // Using app supplied buffer.

                if (m_Buffer == null)
                {
                    // No user buffer is set so unpin any existing single buffer pinning.
                    if (_pinState == PinState.SingleBuffer)
                    {
                        FreeOverlapped(false);
                    }
                }
                else
                {
                    if (_pinState == PinState.SingleBuffer && _pinnedSingleBuffer == m_Buffer)
                    {
                        // This buffer is already pinned - update if offset or count has changed.
                        if (m_Offset != _pinnedSingleBufferOffset)
                        {
                            _pinnedSingleBufferOffset = m_Offset;
                            m_PtrSingleBuffer = Marshal.UnsafeAddrOfPinnedArrayElement(m_Buffer, m_Offset);
                            m_WSABuffer.Pointer = m_PtrSingleBuffer;
                        }
                        if (m_Count != _pinnedSingleBufferCount)
                        {
                            _pinnedSingleBufferCount = m_Count;
                            m_WSABuffer.Length = m_Count;
                        }
                    }
                    else
                    {
                        FreeOverlapped(false);
                        SetupOverlappedSingle(true);
                    }
                }
            }
            else
            {
                // Using internal accept buffer.

                if (!(_pinState == PinState.SingleAcceptBuffer) || !(_pinnedSingleBuffer == m_AcceptBuffer))
                {
                    // Not already pinned - so pin it.
                    FreeOverlapped(false);
                    SetupOverlappedSingle(false);
                }
            }
        }

        // Method to ensure Overlapped object exists with appropriate multiple buffers pinned.
        private void CheckPinMultipleBuffers()
        {
            if (m_BufferList == null)
            {
                // No buffer list is set so unpin any existing multiple buffer pinning.

                if (_pinState == PinState.MultipleBuffer)
                {
                    FreeOverlapped(false);
                }
            }
            else
            {
                if (!(_pinState == PinState.MultipleBuffer) || _bufferListChanged)
                {
                    // Need to setup new Overlapped
                    _bufferListChanged = false;
                    FreeOverlapped(false);
                    try
                    {
                        SetupOverlappedMultiple();
                    }
                    catch (Exception)
                    {
                        FreeOverlapped(false);
                        throw;
                    }
                }
            }
        }

        // Method to ensure Overlapped object exists with appropriate buffers pinned.
        private void CheckPinSendPackets()
        {
            if (_pinState != PinState.None)
            {
                FreeOverlapped(false);
            }
            SetupOverlappedSendPackets();
        }

        // Method to ensure appropriate SocketAddress buffer is pinned.
        private void PinSocketAddressBuffer()
        {
            // Check if already pinned.
            if (_pinnedSocketAddress == m_SocketAddress)
            {
                return;
            }

            // Unpin any existing.
            if (_socketAddressGCHandle.IsAllocated)
            {
                _socketAddressGCHandle.Free();
            }

            // Pin down the new one.
            _socketAddressGCHandle = GCHandle.Alloc(m_SocketAddress.Buffer, GCHandleType.Pinned);
            m_SocketAddress.CopyAddressSizeIntoBuffer();
            m_PtrSocketAddressBuffer = Marshal.UnsafeAddrOfPinnedArrayElement(m_SocketAddress.Buffer, 0);
            m_PtrSocketAddressBufferSize = Marshal.UnsafeAddrOfPinnedArrayElement(m_SocketAddress.Buffer, m_SocketAddress.GetAddressSizeOffset());
            _pinnedSocketAddress = m_SocketAddress;
        }

        // Method to clean up any existing Overlapped object and related state variables.
        private void FreeOverlapped(bool checkForShutdown)
        {
            if (!checkForShutdown || !Environment.HasShutdownStarted)
            {
                // Free the overlapped object

                if (m_PtrNativeOverlapped != null && !m_PtrNativeOverlapped.IsInvalid)
                {
                    m_PtrNativeOverlapped.Dispose();
                    m_PtrNativeOverlapped = null;
                    _pinState = PinState.None;
                    _pinnedAcceptBuffer = null;
                    _pinnedSingleBuffer = null;
                    _pinnedSingleBufferOffset = 0;
                    _pinnedSingleBufferCount = 0;
                }

                if (_preAllocatedOverlapped != null)
                {
                    _preAllocatedOverlapped.Dispose();
                }

                // Free any alloc'd GCHandles

                if (_socketAddressGCHandle.IsAllocated)
                {
                    _socketAddressGCHandle.Free();
                }
                if (_WSAMessageBufferGCHandle.IsAllocated)
                {
                    _WSAMessageBufferGCHandle.Free();
                }
                if (_WSARecvMsgWSABufferArrayGCHandle.IsAllocated)
                {
                    _WSARecvMsgWSABufferArrayGCHandle.Free();
                }
                if (_controlBufferGCHandle.IsAllocated)
                {
                    _controlBufferGCHandle.Free();
                }
            }
        }

        // Method to setup an Overlapped object with either m_Buffer or m_AcceptBuffer pinned.        
        unsafe private void SetupOverlappedSingle(bool pinSingleBuffer)
        {
            // Pin buffer, get native pointers, and fill in WSABuffer descriptor.
            if (pinSingleBuffer)
            {
                if (m_Buffer != null)
                {
                    _preAllocatedOverlapped = new PreAllocatedOverlapped(CompletionPortCallback, this, m_Buffer);
                    GlobalLog.Print(
                        "SocketAsyncEventArgs#" + Logging.HashString(this) +
                        "::SetupOverlappedSingle: new PreAllocatedOverlapped pinSingleBuffer=true, non-null buffer: " +
                        Logging.HashString(_preAllocatedOverlapped));

                    _pinnedSingleBuffer = m_Buffer;
                    _pinnedSingleBufferOffset = m_Offset;
                    _pinnedSingleBufferCount = m_Count;
                    m_PtrSingleBuffer = Marshal.UnsafeAddrOfPinnedArrayElement(m_Buffer, m_Offset);
                    m_PtrAcceptBuffer = IntPtr.Zero;
                    m_WSABuffer.Pointer = m_PtrSingleBuffer;
                    m_WSABuffer.Length = m_Count;
                    _pinState = PinState.SingleBuffer;
                }
                else
                {
                    _preAllocatedOverlapped = new PreAllocatedOverlapped(CompletionPortCallback, this, null);
                    GlobalLog.Print(
                        "SocketAsyncEventArgs#" + Logging.HashString(this) +
                        "::SetupOverlappedSingle: new PreAllocatedOverlapped pinSingleBuffer=true, null buffer: " +
                        Logging.HashString(_preAllocatedOverlapped));

                    _pinnedSingleBuffer = null;
                    _pinnedSingleBufferOffset = 0;
                    _pinnedSingleBufferCount = 0;
                    m_PtrSingleBuffer = IntPtr.Zero;
                    m_PtrAcceptBuffer = IntPtr.Zero;
                    m_WSABuffer.Pointer = m_PtrSingleBuffer;
                    m_WSABuffer.Length = m_Count;
                    _pinState = PinState.NoBuffer;
                }
            }
            else
            {
                _preAllocatedOverlapped = new PreAllocatedOverlapped(CompletionPortCallback, this, m_AcceptBuffer);
                GlobalLog.Print(
                    "SocketAsyncEventArgs#" + Logging.HashString(this) +
                    "::SetupOverlappedSingle: new PreAllocatedOverlapped pinSingleBuffer=false: " +
                    Logging.HashString(_preAllocatedOverlapped));

                _pinnedAcceptBuffer = m_AcceptBuffer;
                m_PtrAcceptBuffer = Marshal.UnsafeAddrOfPinnedArrayElement(m_AcceptBuffer, 0);
                m_PtrSingleBuffer = IntPtr.Zero;
                _pinState = PinState.SingleAcceptBuffer;
            }
        }

        // Method to setup an Overlapped object with with multiple buffers pinned.        
        unsafe private void SetupOverlappedMultiple()
        {
            ArraySegment<byte>[] tempList = new ArraySegment<byte>[m_BufferList.Count];
            m_BufferList.CopyTo(tempList, 0);

            // Number of things to pin is number of buffers.
            // Ensure we have properly sized object array.
            if (_objectsToPin == null || (_objectsToPin.Length != tempList.Length))
            {
                _objectsToPin = new object[tempList.Length];
            }

            // Fill in object array.
            for (int i = 0; i < (tempList.Length); i++)
            {
                _objectsToPin[i] = tempList[i].Array;
            }

            if (m_WSABufferArray == null || m_WSABufferArray.Length != tempList.Length)
            {
                m_WSABufferArray = new WSABuffer[tempList.Length];
            }

            // Pin buffers and fill in WSABuffer descriptor pointers and lengths
            _preAllocatedOverlapped = new PreAllocatedOverlapped(CompletionPortCallback, this, _objectsToPin);
            GlobalLog.Print(
                "SocketAsyncEventArgs#" + Logging.HashString(this) + "::SetupOverlappedMultiple: new PreAllocatedOverlapped." +
                Logging.HashString(_preAllocatedOverlapped));

            for (int i = 0; i < tempList.Length; i++)
            {
                ArraySegment<byte> localCopy = tempList[i];
                RangeValidationHelpers.ValidateSegment(localCopy);
                m_WSABufferArray[i].Pointer = Marshal.UnsafeAddrOfPinnedArrayElement(localCopy.Array, localCopy.Offset);
                m_WSABufferArray[i].Length = localCopy.Count;
            }
            _pinState = PinState.MultipleBuffer;
        }

        // Method to setup an Overlapped object for SendPacketsAsync.        
        unsafe private void SetupOverlappedSendPackets()
        {
            int index;

            // Alloc native descriptor.
            m_SendPacketsDescriptor =
                new Interop.Winsock.TransmitPacketsElement[m_SendPacketsElementsFileCount + m_SendPacketsElementsBufferCount];

            // Number of things to pin is number of buffers + 1 (native descriptor).
            // Ensure we have properly sized object array.
            if (_objectsToPin == null || (_objectsToPin.Length != m_SendPacketsElementsBufferCount + 1))
            {
                _objectsToPin = new object[m_SendPacketsElementsBufferCount + 1];
            }

            // Fill in objects to pin array. Native descriptor buffer first and then user specified buffers.
            _objectsToPin[0] = m_SendPacketsDescriptor;
            index = 1;
            foreach (SendPacketsElement spe in _sendPacketsElementsInternal)
            {
                if (spe != null && spe.m_Buffer != null && spe.m_Count > 0)
                {
                    _objectsToPin[index] = spe.m_Buffer;
                    index++;
                }
            }

            // Pin buffers
            _preAllocatedOverlapped = new PreAllocatedOverlapped(CompletionPortCallback, this, _objectsToPin);
            GlobalLog.Print(
                "SocketAsyncEventArgs#" + Logging.HashString(this) + "::SetupOverlappedSendPackets: new PreAllocatedOverlapped: " +
                Logging.HashString(_preAllocatedOverlapped));

            // Get pointer to native descriptor.
            m_PtrSendPacketsDescriptor = Marshal.UnsafeAddrOfPinnedArrayElement(m_SendPacketsDescriptor, 0);

            // Fill in native descriptor.
            int descriptorIndex = 0;
            int fileIndex = 0;
            foreach (SendPacketsElement spe in _sendPacketsElementsInternal)
            {
                if (spe != null)
                {
                    if (spe.m_Buffer != null && spe.m_Count > 0)
                    {
                        // a buffer
                        m_SendPacketsDescriptor[descriptorIndex].buffer = Marshal.UnsafeAddrOfPinnedArrayElement(spe.m_Buffer, spe.m_Offset);
                        m_SendPacketsDescriptor[descriptorIndex].length = (uint)spe.m_Count;
                        m_SendPacketsDescriptor[descriptorIndex].flags = spe.m_Flags;
                        descriptorIndex++;
                    }
                    else if (spe.m_FilePath != null)
                    {
                        // a file
                        m_SendPacketsDescriptor[descriptorIndex].fileHandle = m_SendPacketsFileHandles[fileIndex].DangerousGetHandle();
                        m_SendPacketsDescriptor[descriptorIndex].fileOffset = spe.m_Offset;
                        m_SendPacketsDescriptor[descriptorIndex].length = (uint)spe.m_Count;
                        m_SendPacketsDescriptor[descriptorIndex].flags = spe.m_Flags;
                        fileIndex++;
                        descriptorIndex++;
                    }
                }
            }

            _pinState = PinState.SendPackets;
        }

        internal void LogBuffer(int size)
        {
            switch (_pinState)
            {
                case PinState.SingleAcceptBuffer:
                    Logging.Dump(Logging.Sockets, _currentSocket, "FinishOperation(" + _completedOperation + "Async)", m_AcceptBuffer, 0, size);
                    break;
                case PinState.SingleBuffer:
                    Logging.Dump(Logging.Sockets, _currentSocket, "FinishOperation(" + _completedOperation + "Async)", m_Buffer, m_Offset, size);
                    break;
                case PinState.MultipleBuffer:
                    foreach (WSABuffer wsaBuffer in m_WSABufferArray)
                    {
                        Logging.Dump(Logging.Sockets, _currentSocket, "FinishOperation(" + _completedOperation + "Async)", wsaBuffer.Pointer, Math.Min(wsaBuffer.Length, size));
                        if ((size -= wsaBuffer.Length) <= 0)
                            break;
                    }
                    break;
                default:
                    break;
            }
        }

        internal void LogSendPacketsBuffers(int size)
        {
            foreach (SendPacketsElement spe in _sendPacketsElementsInternal)
            {
                if (spe != null)
                {
                    if (spe.m_Buffer != null && spe.m_Count > 0)
                    {
                        // a buffer
                        Logging.Dump(Logging.Sockets, _currentSocket, "FinishOperation(" + _completedOperation + "Async)Buffer", spe.m_Buffer, spe.m_Offset, Math.Min(spe.m_Count, size));
                    }
                    else if (spe.m_FilePath != null)
                    {
                        // a file
                        Logging.PrintInfo(Logging.Sockets, _currentSocket, "FinishOperation(" + _completedOperation + "Async)", SR.Format(SR.net_log_socket_not_logged_file, spe.m_FilePath));
                    }
                }
            }
        }

        private SocketError FinishAcceptOperation(Internals.SocketAddress remoteSocketAddress)
        {
            SocketError socketError;
            IntPtr localAddr;
            int localAddrLength;
            IntPtr remoteAddr;

            try
            {
                _currentSocket.GetAcceptExSockaddrs(
                    m_PtrSingleBuffer != IntPtr.Zero ? m_PtrSingleBuffer : m_PtrAcceptBuffer,
                    m_Count != 0 ? m_Count - m_AcceptAddressBufferCount : 0,
                    m_AcceptAddressBufferCount / 2,
                    m_AcceptAddressBufferCount / 2,
                    out localAddr,
                    out localAddrLength,
                    out remoteAddr,
                    out remoteSocketAddress.InternalSize
                    );
                Marshal.Copy(remoteAddr, remoteSocketAddress.Buffer, 0, remoteSocketAddress.Size);

                // Set the socket context.
                IntPtr handle = _currentSocket.SafeHandle.DangerousGetHandle();

                socketError = Interop.Winsock.setsockopt(
                    m_AcceptSocket.SafeHandle,
                    SocketOptionLevel.Socket,
                    SocketOptionName.UpdateAcceptContext,
                    ref handle,
                    Marshal.SizeOf(handle));

                if (socketError == SocketError.SocketError)
                {
                    socketError = SocketPal.GetLastSocketError();
                }
            }
            catch (ObjectDisposedException)
            {
                socketError = SocketError.OperationAborted;
            }

            return socketError;
        }

        private SocketError FinishConnectOperation()
        {
            SocketError socketError;

            // Update the socket context.
            try
            {
                socketError = Interop.Winsock.setsockopt(
                    _currentSocket.SafeHandle,
                    SocketOptionLevel.Socket,
                    SocketOptionName.UpdateConnectContext,
                    null,
                    0);
                if (socketError == SocketError.SocketError)
                {
                    socketError = SocketPal.GetLastSocketError();
                }
            }
            catch (ObjectDisposedException)
            {
                socketError = SocketError.OperationAborted;
            }

            return socketError;
        }

        private unsafe int GetSocketAddressSize()
        {
            return *(int*)m_PtrSocketAddressBufferSize;
        }

        private unsafe void FinishReceiveMessageFromOperation()
        {
            IPAddress address = null;
            Interop.Winsock.WSAMsg* PtrMessage = (Interop.Winsock.WSAMsg*)Marshal.UnsafeAddrOfPinnedArrayElement(_WSAMessageBuffer, 0);

            //ipv4
            if (_controlBuffer.Length == s_ControlDataSize)
            {
                Interop.Winsock.ControlData controlData = Marshal.PtrToStructure<Interop.Winsock.ControlData>(PtrMessage->controlBuffer.Pointer);
                if (controlData.length != UIntPtr.Zero)
                {
                    address = new IPAddress((long)controlData.address);
                }
                _receiveMessageFromPacketInfo = new IPPacketInformation(((address != null) ? address : IPAddress.None), (int)controlData.index);
            }
            //ipv6
            else if (_controlBuffer.Length == s_ControlDataIPv6Size)
            {
                Interop.Winsock.ControlDataIPv6 controlData = Marshal.PtrToStructure<Interop.Winsock.ControlDataIPv6>(PtrMessage->controlBuffer.Pointer);
                if (controlData.length != UIntPtr.Zero)
                {
                    address = new IPAddress(controlData.address);
                }
                _receiveMessageFromPacketInfo = new IPPacketInformation(((address != null) ? address : IPAddress.IPv6None), (int)controlData.index);
            }
            //other
            else
            {
                _receiveMessageFromPacketInfo = new IPPacketInformation();
            }
        }

        private void FinishSendPacketsOperation()
        {
            // Close the files if open
            if (m_SendPacketsFileStreams != null)
            {
                for (int i = 0; i < m_SendPacketsElementsFileCount; i++)
                {
                    // Dereference handles
                    m_SendPacketsFileHandles[i] = null;
                    // Close any open streams
                    if (m_SendPacketsFileStreams[i] != null)
                    {
                        m_SendPacketsFileStreams[i].Dispose();
                        m_SendPacketsFileStreams[i] = null;
                    }
                }
            }
            m_SendPacketsFileStreams = null;
            m_SendPacketsFileHandles = null;
        }

        private unsafe void CompletionPortCallback(uint errorCode, uint numBytes, NativeOverlapped* nativeOverlapped)
        {
#if DEBUG
            GlobalLog.SetThreadSource(ThreadKinds.CompletionPort);
            using (GlobalLog.SetThreadKind(ThreadKinds.System))
            {
                GlobalLog.Enter(
                    "CompletionPortCallback",
                    "errorCode: " + errorCode + ", numBytes: " + numBytes +
                    ", overlapped#" + ((IntPtr)nativeOverlapped).ToString("x"));
#endif
                SocketFlags socketFlags = SocketFlags.None;
                SocketError socketError = (SocketError)errorCode;

                // This is the same NativeOverlapped* as we already have a SafeHandle for, re-use the original.
                Debug.Assert((IntPtr)nativeOverlapped == m_PtrNativeOverlapped.DangerousGetHandle(), "Handle mismatch");

                if (socketError == SocketError.Success)
                {
                    FinishOperationSuccess(socketError, (int)numBytes, socketFlags);
                }
                else
                {
                    if (socketError != SocketError.OperationAborted)
                    {
                        if (_currentSocket.CleanedUp)
                        {
                            socketError = SocketError.OperationAborted;
                        }
                        else
                        {
                            try
                            {
                                // The Async IO completed with a failure.
                                // here we need to call WSAGetOverlappedResult() just so Marshal.GetLastWin32Error() will return the correct error.
                                bool success = Interop.Winsock.WSAGetOverlappedResult(
                                    _currentSocket.SafeHandle,
                                    m_PtrNativeOverlapped,
                                    out numBytes,
                                    false,
                                    out socketFlags);
                                socketError = SocketPal.GetLastSocketError();
                            }
                            catch
                            {
                                // m_CurrentSocket.CleanedUp check above does not always work since this code is subject to race conditions
                                socketError = SocketError.OperationAborted;
                            }
                        }
                    }
                    FinishOperationAsyncFailure(socketError, (int)numBytes, socketFlags);
                }

#if DEBUG
                GlobalLog.Leave("CompletionPortCallback");
            }
#endif
        }
    } // class SocketAsyncContext
}
