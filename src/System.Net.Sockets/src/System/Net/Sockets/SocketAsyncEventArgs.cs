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
        // AcceptSocket property variables.
        internal Socket m_AcceptSocket;
        private Socket _connectSocket;

        // Buffer,Offset,Count property variables.
        internal byte[] m_Buffer;
        internal int m_Count;
        internal int m_Offset;

        // BufferList property variables.
        internal IList<ArraySegment<byte>> m_BufferList;

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

        // Internal SocketAddress buffer
        internal Internals.SocketAddress m_SocketAddress;

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

        private MultipleConnectAsync _multipleConnect;

        private static bool s_LoggingEnabled = Logging.On;

        // Public constructor.
        public SocketAsyncEventArgs()
        {
            // Create callback delegate
            _executionCallback = new ContextCallback(ExecutionCallback);

            InitializeInternals();
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
                    SetupMultipleBuffers();
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
                    SetupSendPacketsElements();
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
                SetupSingleBuffer();
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

            InnerComplete();

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
            FreeInternals(false);

            // Don't bother finalizing later.
            GC.SuppressFinalize(this);
        }

        // Finalizer
        ~SocketAsyncEventArgs()
        {
            FreeInternals(true);
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
            bool userSuppliedBuffer = m_Buffer != null;
            if (userSuppliedBuffer)
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
            }

            InnerStartOperationAccept(userSuppliedBuffer);
        }

        internal void StartOperationConnect()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.Connect;
            _multipleConnect = null;
            _connectSocket = null;

            InnerStartOperationConnect();
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
            InnerStartOperationDisconnect();
        }

        internal void StartOperationReceive()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.Receive;
            InnerStartOperationReceive();
        }

        internal void StartOperationReceiveFrom()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.ReceiveFrom;
            InnerStartOperationReceiveFrom();
        }

        internal void StartOperationReceiveMessageFrom()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.ReceiveMessageFrom;
            InnerStartOperationReceiveMessageFrom();
        }

        internal void StartOperationSend()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.Send;
            InnerStartOperationSend();
        }

        internal void StartOperationSendPackets()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.SendPackets;
            InnerStartOperationSendPackets();
        }

        internal void StartOperationSendTo()
        {
            // Remember the operation type.
            _completedOperation = SocketAsyncOperation.SendTo;
            InnerStartOperationSendTo();
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

                    socketError = FinishOperationAccept(remoteSocketAddress);

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

                    socketError = FinishOperationConnect();

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
                    m_SocketAddress.InternalSize = GetSocketAddressSize();
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
                    m_SocketAddress.InternalSize = GetSocketAddressSize();
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

                    FinishOperationReceiveMessageFrom();
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

                    FinishOperationSendPackets();
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
    } // class SocketAsyncContext
}
