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
    public class SocketAsyncEventArgs : EventArgs, IDisposable
    {
        // Struct sizes needed for some custom marshalling.
        internal static readonly int s_ControlDataSize = Marshal.SizeOf<Interop.Winsock.ControlData>();
        internal static readonly int s_ControlDataIPv6Size = Marshal.SizeOf<Interop.Winsock.ControlDataIPv6>();
        internal static readonly int s_WSAMsgSize = Marshal.SizeOf<Interop.Winsock.WSAMsg>();

        // AcceptSocket property variables.
        internal Socket m_AcceptSocket;
        private Socket _connectSocket;

        // Buffer,Offset,Count property variables.
        internal byte[] m_Buffer;
        internal WSABuffer m_WSABuffer;
        internal IntPtr m_PtrSingleBuffer;
        internal int m_Count;
        internal int m_Offset;

        // BufferList property variables.
        internal IList<ArraySegment<byte>> m_BufferList;
        private bool _bufferListChanged;
        internal WSABuffer[] m_WSABufferArray;

        // BytesTransferred property variables.
        private int _bytesTransferred;

        // Completed event property variables.
        private event EventHandler<SocketAsyncEventArgs> m_Completed;
        private bool _completedChanged;

        // DisconnectReuseSocket propery variables.
        private bool _disconnectReuseSocket;

        // LastOperation property variables.
        private SocketAsyncOperation _completedOperation;

        // ReceiveMessageFromPacketInfo property variables.
        private IPPacketInformation _receiveMessageFromPacketInfo;

        // RemoteEndPoint property variables.
        private EndPoint _remoteEndPoint;

        // SendPacketsFlags property variable.
        internal TransmitFileOptions m_SendPacketsFlags;

        // SendPacketsSendSize property variable.
        internal int m_SendPacketsSendSize;

        // SendPacketsElements property variables.
        internal SendPacketsElement[] m_SendPacketsElements;
        private SendPacketsElement[] _sendPacketsElementsInternal;
        internal int m_SendPacketsElementsFileCount;
        internal int m_SendPacketsElementsBufferCount;

        // SocketError property variables.
        private SocketError _socketError;
        private Exception _connectByNameError;

        // SocketFlags property variables.
        internal SocketFlags m_SocketFlags;

        // UserToken property variables.
        private object _userToken;

        // Internal buffer for AcceptEx when Buffer not supplied.
        internal byte[] m_AcceptBuffer;
        internal int m_AcceptAddressBufferCount;
        internal IntPtr m_PtrAcceptBuffer;

        // Internal SocketAddress buffer
        internal Internals.SocketAddress m_SocketAddress;
        private GCHandle _socketAddressGCHandle;
        private Internals.SocketAddress _pinnedSocketAddress;
        internal IntPtr m_PtrSocketAddressBuffer;
        internal IntPtr m_PtrSocketAddressBufferSize;

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

        // Internal variables for SendPackets
        internal FileStream[] m_SendPacketsFileStreams;
        internal SafeHandle[] m_SendPacketsFileHandles;
        internal Interop.Winsock.TransmitPacketsElement[] m_SendPacketsDescriptor;
        internal IntPtr m_PtrSendPacketsDescriptor;

        // Misc state variables.
        private ExecutionContext _context;
        private ExecutionContext _contextCopy;
        private ContextCallback _executionCallback;
        private Socket _currentSocket;
        private bool _disposeCalled;

        // Controls thread safety via Interlocked
        private const int Configuring = -1;
        private const int Free = 0;
        private const int InProgress = 1;
        private const int Disposed = 2;
        private int _operating;

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

        private MultipleConnectAsync _multipleConnect;

        private static bool s_LoggingEnabled = Logging.On;

        // Public constructor.
        public SocketAsyncEventArgs()
        {
            // Create callback delegate
            _executionCallback = new ContextCallback(ExecutionCallback);

            // Zero tells TransmitPackets to select a default send size.
            m_SendPacketsSendSize = 0;
        }

        // AcceptSocket property.
        public Socket AcceptSocket
        {
            get { return m_AcceptSocket; }
            set { m_AcceptSocket = value; }
        }

        public Socket ConnectSocket
        {
            get { return _connectSocket; }
        }

        // Buffer property.
        public byte[] Buffer
        {
            get { return m_Buffer; }
        }

        // Offset property.
        public int Offset
        {
            get { return m_Offset; }
        }

        // Count property.
        public int Count
        {
            get { return m_Count; }
        }

        // BufferList property.
        // Mutually exclusive with Buffer.
        // Setting this property with an existing non-null Buffer will throw.    
        public IList<ArraySegment<byte>> BufferList
        {
            get { return m_BufferList; }
            set
            {
                StartConfiguring();
                try
                {
                    if (value != null && m_Buffer != null)
                    {
                        throw new ArgumentException(SR.Format(SR.net_ambiguousbuffers, "Buffer"));
                    }
                    m_BufferList = value;
                    _bufferListChanged = true;
                    CheckPinMultipleBuffers();
                }
                finally
                {
                    Complete();
                }
            }
        }

        // BytesTransferred property.
        public int BytesTransferred
        {
            get { return _bytesTransferred; }
        }

        // Completed property.
        public event EventHandler<SocketAsyncEventArgs> Completed
        {
            add
            {
                m_Completed += value;
                _completedChanged = true;
            }
            remove
            {
                m_Completed -= value;
                _completedChanged = true;
            }
        }

        // Method to raise Completed event.
        protected virtual void OnCompleted(SocketAsyncEventArgs e)
        {
            EventHandler<SocketAsyncEventArgs> handler = m_Completed;
            if (handler != null)
            {
                handler(e._currentSocket, e);
            }
        }

        // DisconnectResuseSocket property.
        public bool DisconnectReuseSocket
        {
            get { return _disconnectReuseSocket; }
            set { _disconnectReuseSocket = value; }
        }

        // LastOperation property.
        public SocketAsyncOperation LastOperation
        {
            get { return _completedOperation; }
        }

        // ReceiveMessageFromPacketInfo property.
        public IPPacketInformation ReceiveMessageFromPacketInfo
        {
            get { return _receiveMessageFromPacketInfo; }
        }

        // RemoteEndPoint property.
        public EndPoint RemoteEndPoint
        {
            get { return _remoteEndPoint; }
            set { _remoteEndPoint = value; }
        }

        // SendPacketsElements property.
        public SendPacketsElement[] SendPacketsElements
        {
            get { return m_SendPacketsElements; }
            set
            {
                StartConfiguring();
                try
                {
                    m_SendPacketsElements = value;
                    _sendPacketsElementsInternal = null;
                }
                finally
                {
                    Complete();
                }
            }
        }

        // SendPacketsFlags property.
        public TransmitFileOptions SendPacketsFlags
        {
            get { return m_SendPacketsFlags; }
            set { m_SendPacketsFlags = value; }
        }

        // SendPacketsSendSize property.
        public int SendPacketsSendSize
        {
            get { return m_SendPacketsSendSize; }
            set { m_SendPacketsSendSize = value; }
        }

        // SocketError property.
        public SocketError SocketError
        {
            get { return _socketError; }
            set { _socketError = value; }
        }

        public Exception ConnectByNameError
        {
            get { return _connectByNameError; }
        }

        // SocketFlags property.
        public SocketFlags SocketFlags
        {
            get { return m_SocketFlags; }
            set { m_SocketFlags = value; }
        }

        // UserToken property.
        public object UserToken
        {
            get { return _userToken; }
            set { _userToken = value; }
        }

        // SetBuffer(byte[], int, int) method.
        public void SetBuffer(byte[] buffer, int offset, int count)
        {
            SetBufferInternal(buffer, offset, count);
        }

        // SetBuffer(int, int) method.
        public void SetBuffer(int offset, int count)
        {
            SetBufferInternal(m_Buffer, offset, count);
        }

        private void SetBufferInternal(byte[] buffer, int offset, int count)
        {
            StartConfiguring();
            try
            {
                if (buffer == null)
                {
                    // Clear out existing buffer.
                    m_Buffer = null;
                    m_Offset = 0;
                    m_Count = 0;
                }
                else
                {
                    // Can't have both Buffer and BufferList
                    if (m_BufferList != null)
                    {
                        throw new ArgumentException(SR.Format(SR.net_ambiguousbuffers, "BufferList"));
                    }
                    // Offset and count can't be negative and the 
                    // combination must be in bounds of the array.
                    if (offset < 0 || offset > buffer.Length)
                    {
                        throw new ArgumentOutOfRangeException("offset");
                    }
                    if (count < 0 || count > (buffer.Length - offset))
                    {
                        throw new ArgumentOutOfRangeException("count");
                    }
                    m_Buffer = buffer;
                    m_Offset = offset;
                    m_Count = count;
                }

                // Pin new or unpin old buffer.
                CheckPinSingleBuffer(true);
            }
            finally
            {
                Complete();
            }
        }

        // Method to update internal state after sync or async completion.
        internal void SetResults(SocketError socketError, int bytesTransferred, SocketFlags flags)
        {
            _socketError = socketError;
            _connectByNameError = null;
            _bytesTransferred = bytesTransferred;
            m_SocketFlags = flags;
        }

        internal void SetResults(Exception exception, int bytesTransferred, SocketFlags flags)
        {
            _connectByNameError = exception;
            _bytesTransferred = bytesTransferred;
            m_SocketFlags = flags;

            if (exception == null)
            {
                _socketError = SocketError.Success;
            }
            else
            {
                SocketException socketException = exception as SocketException;
                if (socketException != null)
                {
                    _socketError = socketException.SocketErrorCode;
                }
                else
                {
                    _socketError = SocketError.SocketError;
                }
            }
        }

        // Context callback delegate.
        private void ExecutionCallback(object ignored)
        {
            OnCompleted(this);
        }

        // Method to mark this object as no longer "in-use".
        // Will also execute a Dispose deferred because I/O was in progress.  
        internal void Complete()
        {
            // Mark as not in-use            
            _operating = Free;
            CompleteIOCPOperation();

            // Check for deferred Dispose().
            // The deferred Dispose is not guaranteed if Dispose is called while an operation is in progress. 
            // The m_DisposeCalled variable is not managed in a thread-safe manner on purpose for performance.
            if (_disposeCalled)
            {
                Dispose();
            }
        }

        // Dispose call to implement IDisposable.
        public void Dispose()
        {
            // Remember that Dispose was called.
            _disposeCalled = true;

            // Check if this object is in-use for an async socket operation.
            if (Interlocked.CompareExchange(ref _operating, Disposed, Free) != Free)
            {
                // Either already disposed or will be disposed when current operation completes.
                return;
            }

            // OK to dispose now.
            // Free native overlapped data.
            FreeOverlapped(false);

            // Don't bother finalizing later.
            GC.SuppressFinalize(this);
        }

        // Finalizer
        ~SocketAsyncEventArgs()
        {
            FreeOverlapped(true);
        }

        // Us a try/Finally to make sure Complete is called when you're done
        private void StartConfiguring()
        {
            int status = Interlocked.CompareExchange(ref _operating, Configuring, Free);
            if (status == InProgress || status == Configuring)
            {
                throw new InvalidOperationException(SR.net_socketopinprogress);
            }
            else if (status == Disposed)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }
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

        // Method called to prepare for a native async socket call.
        // This method performs the tasks common to all socket operations.
        internal void StartOperationCommon(Socket socket)
        {
            // Change status to "in-use".
            if (Interlocked.CompareExchange(ref _operating, InProgress, Free) != Free)
            {
                // If it was already "in-use" check if Dispose was called.
                if (_disposeCalled)
                {
                    // Dispose was called - throw ObjectDisposed.
                    throw new ObjectDisposedException(GetType().FullName);
                }

                // Only one at a time.
                throw new InvalidOperationException(SR.net_socketopinprogress);
            }

            // Prepare execution context for callback.

            if (ExecutionContext.IsFlowSuppressed())
            {
                // Fast path for when flow is suppressed.

                _context = null;
                _contextCopy = null;
            }
            else
            {
                // Flow is not suppressed.

                // If event delegates have changed or socket has changed
                // then discard any existing context.

                if (_completedChanged || socket != _currentSocket)
                {
                    _completedChanged = false;
                    _context = null;
                    _contextCopy = null;
                }

                // Capture execution context if none already.

                if (_context == null)
                {
                    _context = ExecutionContext.Capture();
                }

                // If there is an execution context we need a fresh copy for each completion.

                if (_context != null)
                {
                    _contextCopy = _context.CreateCopy();
                }
            }

            // Remember current socket.
            _currentSocket = socket;
        }

        internal void StartOperationAccept()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.Accept;

            // AcceptEx needs a single buffer with room for two special sockaddr data structures.
            // It can also take additional buffer space in front of those special sockaddr 
            // structures that can be filled in with initial data coming in on a connection.

            // First calculate the special AcceptEx address buffer size.
            // It is the size of two native sockaddr buffers with 16 extra bytes each.
            // The native sockaddr buffers vary by address family so must reference the current socket.
            m_AcceptAddressBufferCount = 2 * (_currentSocket.m_RightEndPoint.Serialize().Size + 16);

            // If our caller specified a buffer (willing to get received data with the Accept) then
            // it needs to be large enough for the two special sockaddr buffers that AcceptEx requires.
            // Throw if that buffer is not large enough.  
            if (m_Buffer != null)
            {
                // Caller specified a buffer - see if it is large enough
                if (m_Count < m_AcceptAddressBufferCount)
                {
                    throw new ArgumentException(SR.Format(SR.net_buffercounttoosmall, "Count"));
                }
                // Buffer is already pinned.

            }
            else
            {
                // Caller didn't specify a buffer so use an internal one.
                // See if current internal one is big enough, otherwise create a new one.
                if (m_AcceptBuffer == null || m_AcceptBuffer.Length < m_AcceptAddressBufferCount)
                {
                    m_AcceptBuffer = new byte[m_AcceptAddressBufferCount];
                }
                CheckPinSingleBuffer(false);
            }
        }

        internal void StartOperationConnect()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.Connect;
            _multipleConnect = null;
            _connectSocket = null;

            // ConnectEx uses a sockaddr buffer containing he remote address to which to connect.
            // It can also optionally take a single buffer of data to send after the connection is complete.
            //
            // The sockaddr is pinned with a GCHandle to avoid having to use the object array form of UnsafePack.
            // The optional buffer is pinned using the Overlapped.UnsafePack method that takes a single object to pin.

            PinSocketAddressBuffer();
            CheckPinNoBuffer();
        }

        internal void StartOperationWrapperConnect(MultipleConnectAsync args)
        {
            _completedOperation = SocketAsyncOperation.Connect;
            _multipleConnect = args;
            _connectSocket = null;
        }

        internal void CancelConnectAsync()
        {
            if (_operating == InProgress && _completedOperation == SocketAsyncOperation.Connect)
            {
                if (_multipleConnect != null)
                {
                    // if a multiple connect is in progress, abort it
                    _multipleConnect.Cancel();
                }
                else
                {
                    // otherwise we're doing a normal ConnectAsync - cancel it by closing the socket
                    // m_CurrentSocket will only be null if m_MultipleConnect was set, so we don't have to check
                    GlobalLog.Assert(_currentSocket != null, "SocketAsyncEventArgs::CancelConnectAsync - CurrentSocket and MultipleConnect both null!");
                    _currentSocket.Dispose();
                }
            }
        }

        internal void StartOperationDisconnect()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.Disconnect;
            CheckPinNoBuffer();
        }

        internal void StartOperationReceive()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.Receive;

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

        internal void StartOperationReceiveFrom()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.ReceiveFrom;

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

        internal void StartOperationReceiveMessageFrom()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.ReceiveMessageFrom;

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

        internal void StartOperationSend()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.Send;

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

        internal void StartOperationSendPackets()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.SendPackets;

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

        internal void StartOperationSendTo()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.SendTo;

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

        internal void UpdatePerfCounters(int size, bool sendOp)
        {
#if !FEATURE_PAL // perfcounter
            if (sendOp)
            {
                SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesSent, size);
                if (_currentSocket.Transport == TransportType.Udp)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsSent);
                }
            }
            else
            {
                SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesReceived, size);
                if (_currentSocket.Transport == TransportType.Udp)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsReceived);
                }
            }
#endif
        }

        internal void FinishOperationSyncFailure(SocketError socketError, int bytesTransferred, SocketFlags flags)
        {
            SetResults(socketError, bytesTransferred, flags);

            // this will be null if we're doing a static ConnectAsync to a DnsEndPoint with AddressFamily.Unspecified;
            // the attempt socket will be closed anyways, so not updating the state is OK
            if (_currentSocket != null)
            {
                _currentSocket.UpdateStatusAfterSocketError(socketError);
            }

            Complete();
        }

        internal void FinishConnectByNameSyncFailure(Exception exception, int bytesTransferred, SocketFlags flags)
        {
            SetResults(exception, bytesTransferred, flags);

            if (_currentSocket != null)
            {
                _currentSocket.UpdateStatusAfterSocketError(_socketError);
            }

            Complete();
        }

        internal void FinishOperationAsyncFailure(SocketError socketError, int bytesTransferred, SocketFlags flags)
        {
            SetResults(socketError, bytesTransferred, flags);

            // this will be null if we're doing a static ConnectAsync to a DnsEndPoint with AddressFamily.Unspecified;
            // the attempt socket will be closed anyways, so not updating the state is OK
            if (_currentSocket != null)
            {
                _currentSocket.UpdateStatusAfterSocketError(socketError);
            }

            Complete();
            if (_context == null)
            {
                OnCompleted(this);
            }
            else
            {
                ExecutionContext.Run(_contextCopy, _executionCallback, null);
            }
        }

        internal void FinishOperationAsyncFailure(Exception exception, int bytesTransferred, SocketFlags flags)
        {
            SetResults(exception, bytesTransferred, flags);

            if (_currentSocket != null)
            {
                _currentSocket.UpdateStatusAfterSocketError(_socketError);
            }
            Complete();
            if (_context == null)
            {
                OnCompleted(this);
            }
            else
            {
                ExecutionContext.Run(_contextCopy, _executionCallback, null);
            }
        }

        internal void FinishWrapperConnectSuccess(Socket connectSocket, int bytesTransferred, SocketFlags flags)
        {
            SetResults(SocketError.Success, bytesTransferred, flags);
            _currentSocket = connectSocket;
            _connectSocket = connectSocket;

            // Complete the operation and raise the event
            Complete();
            if (_contextCopy == null)
            {
                OnCompleted(this);
            }
            else
            {
                ExecutionContext.Run(_contextCopy, _executionCallback, null);
            }
        }

        internal void FinishOperationSuccess(SocketError socketError, int bytesTransferred, SocketFlags flags)
        {
            SetResults(socketError, bytesTransferred, flags);

            switch (_completedOperation)
            {
                case SocketAsyncOperation.Accept:


                    if (bytesTransferred > 0)
                    {
                        // Log and Perf counters.
                        if (s_LoggingEnabled) LogBuffer(bytesTransferred);
                        if (Socket.s_PerfCountersEnabled) UpdatePerfCounters(bytesTransferred, false);
                    }

                    // Get the endpoint.
                    Internals.SocketAddress remoteSocketAddress = IPEndPointExtensions.Serialize(_currentSocket.m_RightEndPoint);

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

                    if (socketError == SocketError.Success)
                    {
                        m_AcceptSocket = _currentSocket.UpdateAcceptSocket(m_AcceptSocket, _currentSocket.m_RightEndPoint.Create(remoteSocketAddress));

                        if (s_LoggingEnabled)
                            Logging.PrintInfo(Logging.Sockets, m_AcceptSocket,
          SR.Format(SR.net_log_socket_accepted, m_AcceptSocket.RemoteEndPoint, m_AcceptSocket.LocalEndPoint));
                    }
                    else
                    {
                        SetResults(socketError, bytesTransferred, SocketFlags.None);
                        m_AcceptSocket = null;
                    }
                    break;

                case SocketAsyncOperation.Connect:

                    if (bytesTransferred > 0)
                    {
                        // Log and Perf counters.
                        if (s_LoggingEnabled) LogBuffer(bytesTransferred);
                        if (Socket.s_PerfCountersEnabled) UpdatePerfCounters(bytesTransferred, true);
                    }

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

                    // Mark socket connected.
                    if (socketError == SocketError.Success)
                    {
                        if (s_LoggingEnabled)
                            Logging.PrintInfo(Logging.Sockets, _currentSocket,
          SR.Format(SR.net_log_socket_connected, _currentSocket.LocalEndPoint, _currentSocket.RemoteEndPoint));

                        _currentSocket.SetToConnected();
                        _connectSocket = _currentSocket;
                    }
                    break;

                case SocketAsyncOperation.Disconnect:

                    _currentSocket.SetToDisconnected();
                    _currentSocket.m_RemoteEndPoint = null;

                    break;

                case SocketAsyncOperation.Receive:

                    if (bytesTransferred > 0)
                    {
                        // Log and Perf counters.
                        if (s_LoggingEnabled) LogBuffer(bytesTransferred);
                        if (Socket.s_PerfCountersEnabled) UpdatePerfCounters(bytesTransferred, false);
                    }
                    break;

                case SocketAsyncOperation.ReceiveFrom:

                    if (bytesTransferred > 0)
                    {
                        // Log and Perf counters.
                        if (s_LoggingEnabled) LogBuffer(bytesTransferred);
                        if (Socket.s_PerfCountersEnabled) UpdatePerfCounters(bytesTransferred, false);
                    }

                    // Deal with incoming address.
                    m_SocketAddress.SetSize(m_PtrSocketAddressBufferSize);
                    Internals.SocketAddress socketAddressOriginal = IPEndPointExtensions.Serialize(_remoteEndPoint);
                    if (!socketAddressOriginal.Equals(m_SocketAddress))
                    {
                        try
                        {
                            _remoteEndPoint = _remoteEndPoint.Create(m_SocketAddress);
                        }
                        catch
                        {
                        }
                    }
                    break;

                case SocketAsyncOperation.ReceiveMessageFrom:

                    if (bytesTransferred > 0)
                    {
                        // Log and Perf counters.
                        if (s_LoggingEnabled) LogBuffer(bytesTransferred);
                        if (Socket.s_PerfCountersEnabled) UpdatePerfCounters(bytesTransferred, false);
                    }

                    // Deal with incoming address.
                    m_SocketAddress.SetSize(m_PtrSocketAddressBufferSize);
                    socketAddressOriginal = IPEndPointExtensions.Serialize(_remoteEndPoint);
                    if (!socketAddressOriginal.Equals(m_SocketAddress))
                    {
                        try
                        {
                            _remoteEndPoint = _remoteEndPoint.Create(m_SocketAddress);
                        }
                        catch
                        {
                        }
                    }

                    // Extract the packet information.
                    unsafe
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
                    break;

                case SocketAsyncOperation.Send:

                    if (bytesTransferred > 0)
                    {
                        // Log and Perf counters.
                        if (s_LoggingEnabled) LogBuffer(bytesTransferred);
                        if (Socket.s_PerfCountersEnabled) UpdatePerfCounters(bytesTransferred, true);
                    }
                    break;

                case SocketAsyncOperation.SendPackets:

                    if (bytesTransferred > 0)
                    {
                        // Log and Perf counters.
                        if (s_LoggingEnabled) LogSendPacketsBuffers(bytesTransferred);
                        if (Socket.s_PerfCountersEnabled) UpdatePerfCounters(bytesTransferred, true);
                    }

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

                    break;

                case SocketAsyncOperation.SendTo:

                    if (bytesTransferred > 0)
                    {
                        // Log and Perf counters.
                        if (s_LoggingEnabled) LogBuffer(bytesTransferred);
                        if (Socket.s_PerfCountersEnabled) UpdatePerfCounters(bytesTransferred, true);
                    }
                    break;
            }

            if (socketError != SocketError.Success)
            {
                // Asynchronous failure or something went wrong after async success.
                SetResults(socketError, bytesTransferred, flags);
                _currentSocket.UpdateStatusAfterSocketError(socketError);
            }

            // Complete the operation and raise completion event.
            Complete();
            if (_contextCopy == null)
            {
                OnCompleted(this);
            }
            else
            {
                ExecutionContext.Run(_contextCopy, _executionCallback, null);
            }
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
