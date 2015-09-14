// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

//------------------------------------------------------------------------------
// </copyright>
//------------------------------------------------------------------------------

namespace System.Net.Sockets
{
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
    using Internals;

    /// <devdoc>
    /// <para>The <see cref='Sockets.Socket'/> class implements the Berkeley sockets
    ///    interface.</para>
    /// </devdoc>
    public partial class Socket : IDisposable
    {
        internal const int DefaultCloseTimeout = -1; // don't change for default, otherwise breaking change

        // AcceptQueue - queued list of accept requests for BeginAccept or async Result for Begin Connect
        private object _acceptQueueOrConnectResult;

        // the following 8 members represent the state of the socket
        private SafeCloseSocket _handle;

        // m_RightEndPoint is null if the socket has not been bound.  Otherwise, it is any EndPoint of the
        // correct type (IPEndPoint, etc).
        internal EndPoint m_RightEndPoint;
        internal EndPoint m_RemoteEndPoint;
        // this flags monitor if the socket was ever connected at any time and if it still is.
        private bool _isConnected; //  = false;
        private bool _isDisconnected; //  = false;

        // when the socket is created it will be in blocking mode
        // we'll only be able to Accept or Connect, so we only need
        // to handle one of these cases at a time
        private bool _willBlock = true; // desired state of the socket for the user
        private bool _willBlockInternal = true; // actual win32 state of the socket
        private bool _isListening = false;

        // Our internal state doesn't automatically get updated after a non-blocking connect
        // completes.  Keep track of whether we're doing a non-blocking connect, and make sure
        // to poll for the real state until we're done connecting.
        private bool _nonBlockingConnectInProgress;

        // Keep track of the kind of endpoint used to do a non-blocking connect, so we can set
        // it to m_RightEndPoint when we discover we're connected.
        private EndPoint _nonBlockingConnectRightEndPoint;

        // These are constants initialized by constructor
        private AddressFamily _addressFamily;
        private SocketType _socketType;
        private ProtocolType _protocolType;

        // These caches are one degree off of Socket since they're not used in the sync case/when disabled in config.
        private CacheSet _caches;

        private class CacheSet
        {
            internal CallbackClosure ConnectClosureCache;
            internal CallbackClosure AcceptClosureCache;
            internal CallbackClosure SendClosureCache;
            internal CallbackClosure ReceiveClosureCache;
        }

        // Bool marked true if the native socket option IP_PKTINFO or IPV6_PKTINFO has been set
        private bool _receivingPacketInformation;

        //These members are to cache permission checks
        private Internals.SocketAddress _permittedRemoteAddress;

        private static object s_InternalSyncObject;
        private int _closeTimeout = Socket.DefaultCloseTimeout;
        private int _intCleanedUp;                 // 0 if not completed >0 otherwise.

        internal static volatile bool s_Initialized;
        private static volatile bool s_LoggingEnabled;
#if !FEATURE_PAL // perfcounter
        internal static volatile bool s_PerfCountersEnabled;
#endif

        #region Constructors
        public Socket(SocketType socketType, ProtocolType protocolType)
            : this(AddressFamily.InterNetworkV6, socketType, protocolType)
        {
            DualMode = true;
        }

        /// <devdoc>
        ///    <para>
        ///       Initializes a new instance of the <see cref='Sockets.Socket'/> class.
        ///    </para>
        /// </devdoc>
        public Socket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
        {
            s_LoggingEnabled = Logging.On;
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Socket", addressFamily);

            InitializeSockets();
            _handle = SocketPal.CreateSocket(addressFamily, socketType, protocolType);

            _addressFamily = addressFamily;
            _socketType = socketType;
            _protocolType = protocolType;

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Socket", null);
        }

        public Socket(SocketInformation socketInformation)
        {
            s_LoggingEnabled = Logging.On;
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Socket", _addressFamily);

            InitializeSockets();
            if (socketInformation.ProtocolInformation == null || socketInformation.ProtocolInformation.Length < SocketPal.ProtocolInformationSize)
            {
                throw new ArgumentException(SR.net_sockets_invalid_socketinformation, "socketInformation.ProtocolInformation");
            }

            _handle = SocketPal.CreateSocket(socketInformation, out _addressFamily, out _socketType, out _protocolType);

            if (_addressFamily != AddressFamily.InterNetwork && _addressFamily != AddressFamily.InterNetworkV6)
            {
                throw new NotSupportedException(SR.net_invalidversion);
            }

            _isConnected = socketInformation.IsConnected;
            _willBlock = !socketInformation.IsNonBlocking;
            InternalSetBlocking(_willBlock);
            _isListening = socketInformation.IsListening;

            //are we bound?  if so, what's the local endpoint?
            if (socketInformation.RemoteEndPoint != null)
            {
                m_RightEndPoint = socketInformation.RemoteEndPoint;
                m_RemoteEndPoint = socketInformation.RemoteEndPoint;
            }
            else
            {
                EndPoint ep = null;
                if (_addressFamily == AddressFamily.InterNetwork)
                {
                    ep = IPEndPointStatics.Any;
                }
                else if (_addressFamily == AddressFamily.InterNetworkV6)
                {
                    ep = IPEndPointStatics.IPv6Any;
                }

                Internals.SocketAddress socketAddress = IPEndPointExtensions.Serialize(ep);
                SocketError errorCode;
                try
                {
                    errorCode = SocketPal.GetSockName(
                        _handle,
                        socketAddress.Buffer,
                        ref socketAddress.InternalSize);
                }
                catch (ObjectDisposedException)
                {
                    errorCode = SocketError.NotSocket;
                }

                if (errorCode == SocketError.Success)
                {
                    try
                    {
                        //we're bound
                        m_RightEndPoint = ep.Create(socketAddress);
                    }
                    catch
                    {
                    }
                }
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Socket", null);
        }

        /// <devdoc>
        ///    <para>
        ///       Called by the class to create a socket to accept an
        ///       incoming request.
        ///    </para>
        /// </devdoc>
        private Socket(SafeCloseSocket fd)
        {
            s_LoggingEnabled = Logging.On;
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Socket", null);
            InitializeSockets();
            // ExceptionHelper.UnmanagedPermission.Demand();
            //<CONSIDER>if this ctor is re-publicized/protected, check
            // that fd is valid socket handle.
            // getsockopt(fd, SOL_SOCKET, SO_ERROR, &dwError, &dwErrorSize)
            // would work
            //</CONSIDER>

            //
            // this should never happen, let's check anyway
            //
            if (fd == null || fd.IsInvalid)
            {
                throw new ArgumentException(SR.net_InvalidSocketHandle);
            }

            _handle = fd;

            _addressFamily = Sockets.AddressFamily.Unknown;
            _socketType = Sockets.SocketType.Unknown;
            _protocolType = Sockets.ProtocolType.Unknown;
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Socket", null);
        }

        #endregion

        #region Properties

        // Renamed to be consistent with OSSupportsIPv6
        public static bool OSSupportsIPv4
        {
            get
            {
                InitializeSockets();
                return SocketProtocolSupportPal.OSSupportsIPv4;
            }
        }

        public static bool OSSupportsIPv6
        {
            get
            {
                InitializeSockets();
                return SocketProtocolSupportPal.OSSupportsIPv6;
            }
        }

        /// <devdoc>
        ///    <para>
        ///       Gets the amount of data pending in the network's input buffer that can be
        ///       read from the socket.
        ///    </para>
        /// </devdoc>
        public int Available
        {
            get
            {
                if (CleanedUp)
                {
                    throw new ObjectDisposedException(this.GetType().FullName);
                }

                int argp;

                // This may throw ObjectDisposedException.
                SocketError errorCode = SocketPal.GetAvailable(_handle, out argp);

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Available_get() Interop.Winsock.ioctlsocket returns errorCode:" + errorCode);

                //
                // if the native call fails we'll throw a SocketException
                //
                if (errorCode != SocketError.Success)
                {
                    //
                    // update our internal state after this socket error and throw
                    //
                    SocketException socketException = new SocketException((int)errorCode);
                    UpdateStatusAfterSocketError(socketException);
                    if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "Available", socketException);
                    throw socketException;
                }

                return argp;
            }
        }

        /// <devdoc>
        ///    <para>
        ///       Gets the local end point.
        ///    </para>
        /// </devdoc>
        public EndPoint LocalEndPoint
        {
            get
            {
                if (CleanedUp)
                {
                    throw new ObjectDisposedException(this.GetType().FullName);
                }

                if (_nonBlockingConnectInProgress && Poll(0, SelectMode.SelectWrite))
                {
                    // update the state if we've become connected after a non-blocking connect
                    _isConnected = true;
                    m_RightEndPoint = _nonBlockingConnectRightEndPoint;
                    _nonBlockingConnectInProgress = false;
                }

                if (m_RightEndPoint == null)
                {
                    return null;
                }

                Internals.SocketAddress socketAddress = IPEndPointExtensions.Serialize(m_RightEndPoint);

                // This may throw ObjectDisposedException.
                SocketError errorCode = SocketPal.GetSockName(
                    _handle,
                    socketAddress.Buffer,
                    ref socketAddress.InternalSize);

                if (errorCode != SocketError.Success)
                {
                    //
                    // update our internal state after this socket error and throw
                    //
                    SocketException socketException = new SocketException((int)errorCode);
                    UpdateStatusAfterSocketError(socketException);
                    if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "LocalEndPoint", socketException);
                    throw socketException;
                }

                return m_RightEndPoint.Create(socketAddress);
            }
        }

        /// <devdoc>
        ///    <para>
        ///       Gets the remote end point
        ///    </para>
        /// </devdoc>
        public EndPoint RemoteEndPoint
        {
            get
            {
                if (CleanedUp)
                {
                    throw new ObjectDisposedException(this.GetType().FullName);
                }

                if (m_RemoteEndPoint == null)
                {
                    if (_nonBlockingConnectInProgress && Poll(0, SelectMode.SelectWrite))
                    {
                        // update the state if we've become connected after a non-blocking connect
                        _isConnected = true;
                        m_RightEndPoint = _nonBlockingConnectRightEndPoint;
                        _nonBlockingConnectInProgress = false;
                    }

                    if (m_RightEndPoint == null)
                    {
                        return null;
                    }

                    Internals.SocketAddress socketAddress = IPEndPointExtensions.Serialize(m_RightEndPoint);

                    // This may throw ObjectDisposedException.
                    SocketError errorCode = SocketPal.GetPeerName(
                        _handle,
                        socketAddress.Buffer,
                        ref socketAddress.InternalSize);

                    if (errorCode != SocketError.Success)
                    {
                        //
                        // update our internal state after this socket error and throw
                        //
                        SocketException socketException = new SocketException((int)errorCode);
                        UpdateStatusAfterSocketError(socketException);
                        if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "RemoteEndPoint", socketException);
                        throw socketException;
                    }

                    try
                    {
                        m_RemoteEndPoint = m_RightEndPoint.Create(socketAddress);
                    }
                    catch
                    {
                    }
                }

                return m_RemoteEndPoint;
            }
        }

        internal SafeCloseSocket SafeHandle
        {
            get
            {
                return _handle;
            }
        }

        // Non-blocking I/O control
        /// <devdoc>
        ///    <para>
        ///       Gets and sets the blocking mode of a socket.
        ///    </para>
        /// </devdoc>
        public bool Blocking
        {
            get
            {
                //
                // return the user's desired blocking behaviour (not the actual win32 state)
                //
                return _willBlock;
            }
            set
            {
                if (CleanedUp)
                {
                    throw new ObjectDisposedException(this.GetType().FullName);
                }

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::set_Blocking() value:" + value.ToString() + " willBlock:" + _willBlock.ToString() + " willBlockInternal:" + _willBlockInternal.ToString());

                bool current;

                SocketError errorCode = InternalSetBlocking(value, out current);

                if (errorCode != SocketError.Success)
                {
                    //
                    // update our internal state after this socket error and throw
                    SocketException socketException = new SocketException((int)errorCode);
                    UpdateStatusAfterSocketError(socketException);
                    if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "Blocking", socketException);
                    throw socketException;
                }

                //
                // win32 call succeeded, update desired state
                //
                _willBlock = current;
            }
        }

        /// <devdoc>
        ///    <para>
        ///       Gets the connection state of the Socket. This property will return the latest
        ///       known state of the Socket. When it returns false, the Socket was either never connected
        ///       or it is not connected anymore. When it returns true, though, there's no guarantee that the Socket
        ///       is still connected, but only that it was connected at the time of the last IO operation.
        ///    </para>
        /// </devdoc>
        public bool Connected
        {
            get
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Connected() m_IsConnected:" + _isConnected);

                if (_nonBlockingConnectInProgress && Poll(0, SelectMode.SelectWrite))
                {
                    // update the state if we've become connected after a non-blocking connect
                    _isConnected = true;
                    m_RightEndPoint = _nonBlockingConnectRightEndPoint;
                    _nonBlockingConnectInProgress = false;
                }

                return _isConnected;
            }
        }

        /// <devdoc>
        ///    <para>
        ///       Gets the socket's address family.
        ///    </para>
        /// </devdoc>
        public AddressFamily AddressFamily
        {
            get
            {
                return _addressFamily;
            }
        }

        /// <devdoc>
        ///    <para>
        ///       Gets the socket's socketType.
        ///    </para>
        /// </devdoc>
        public SocketType SocketType
        {
            get
            {
                return _socketType;
            }
        }

        /// <devdoc>
        ///    <para>
        ///       Gets the socket's protocol socketType.
        ///    </para>
        /// </devdoc>
        public ProtocolType ProtocolType
        {
            get
            {
                return _protocolType;
            }
        }

        public bool IsBound
        {
            get
            {
                return (m_RightEndPoint != null);
            }
        }

        public bool ExclusiveAddressUse
        {
            get
            {
                return (int)GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse) != 0 ? true : false;
            }
            set
            {
                if (IsBound)
                {
                    throw new InvalidOperationException(SR.net_sockets_mustnotbebound);
                }
                SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.ExclusiveAddressUse, value ? 1 : 0);
            }
        }

        public int ReceiveBufferSize
        {
            get
            {
                return (int)GetSocketOption(SocketOptionLevel.Socket,
                                     SocketOptionName.ReceiveBuffer);
            }
            set
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException("value");
                }

                SetSocketOption(SocketOptionLevel.Socket,
                                  SocketOptionName.ReceiveBuffer, value);
            }
        }

        public int SendBufferSize
        {
            get
            {
                return (int)GetSocketOption(SocketOptionLevel.Socket,
                                     SocketOptionName.SendBuffer);
            }

            set
            {
                if (value < 0)
                {
                    throw new ArgumentOutOfRangeException("value");
                }

                SetSocketOption(SocketOptionLevel.Socket,
                                  SocketOptionName.SendBuffer, value);
            }
        }

        public int ReceiveTimeout
        {
            get
            {
                return (int)GetSocketOption(SocketOptionLevel.Socket,
                                     SocketOptionName.ReceiveTimeout);
            }
            set
            {
                if (value < -1)
                {
                    throw new ArgumentOutOfRangeException("value");
                }
                if (value == -1)
                {
                    value = 0;
                }

                SetSocketOption(SocketOptionLevel.Socket,
                                  SocketOptionName.ReceiveTimeout, value);
            }
        }

        public int SendTimeout
        {
            get
            {
                return (int)GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout);
            }

            set
            {
                if (value < -1)
                {
                    throw new ArgumentOutOfRangeException("value");
                }
                if (value == -1)
                {
                    value = 0;
                }

                SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.SendTimeout, value);
            }
        }

        public LingerOption LingerState
        {
            get
            {
                return (LingerOption)GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Linger);
            }
            set
            {
                SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Linger, value);
            }
        }

        public bool NoDelay
        {
            get
            {
                return (int)GetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay) != 0 ? true : false;
            }
            set
            {
                SetSocketOption(SocketOptionLevel.Tcp, SocketOptionName.NoDelay, value ? 1 : 0);
            }
        }

        public short Ttl
        {
            get
            {
                if (_addressFamily == AddressFamily.InterNetwork)
                {
                    return (short)(int)GetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive);
                }
                else if (_addressFamily == AddressFamily.InterNetworkV6)
                {
                    return (short)(int)GetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IpTimeToLive);
                }
                else
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }
            }

            set
            {
                // valid values are from 0 to 255 since Ttl is really just a byte value on the wire
                if (value < 0 || value > 255)
                {
                    throw new ArgumentOutOfRangeException("value");
                }

                if (_addressFamily == AddressFamily.InterNetwork)
                {
                    SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IpTimeToLive, value);
                }

                else if (_addressFamily == AddressFamily.InterNetworkV6)
                {
                    SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IpTimeToLive, value);
                }
                else
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }
            }
        }

        public bool DontFragment
        {
            get
            {
                if (_addressFamily == AddressFamily.InterNetwork)
                {
                    return (int)GetSocketOption(SocketOptionLevel.IP, SocketOptionName.DontFragment) != 0 ? true : false;
                }
                else
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }
            }

            set
            {
                if (_addressFamily == AddressFamily.InterNetwork)
                {
                    SetSocketOption(SocketOptionLevel.IP, SocketOptionName.DontFragment, value ? 1 : 0);
                }
                else
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }
            }
        }

        public bool MulticastLoopback
        {
            get
            {
                if (_addressFamily == AddressFamily.InterNetwork)
                {
                    return (int)GetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback) != 0 ? true : false;
                }
                else if (_addressFamily == AddressFamily.InterNetworkV6)
                {
                    return (int)GetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback) != 0 ? true : false;
                }
                else
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }
            }

            set
            {
                if (_addressFamily == AddressFamily.InterNetwork)
                {
                    SetSocketOption(SocketOptionLevel.IP, SocketOptionName.MulticastLoopback, value ? 1 : 0);
                }

                else if (_addressFamily == AddressFamily.InterNetworkV6)
                {
                    SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.MulticastLoopback, value ? 1 : 0);
                }
                else
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }
            }
        }

        public bool EnableBroadcast
        {
            get
            {
                return (int)GetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast) != 0 ? true : false;
            }
            set
            {
                SetSocketOption(SocketOptionLevel.Socket, SocketOptionName.Broadcast, value ? 1 : 0);
            }
        }

        public bool DualMode
        {
            get
            {
                if (AddressFamily != AddressFamily.InterNetworkV6)
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }
                return ((int)GetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only) == 0);
            }
            set
            {
                if (AddressFamily != AddressFamily.InterNetworkV6)
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }
                SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, value ? 0 : 1);
            }
        }

        private bool IsDualMode
        {
            get
            {
                return AddressFamily == AddressFamily.InterNetworkV6 && DualMode;
            }
        }

        internal bool CanTryAddressFamily(AddressFamily family)
        {
            return (family == _addressFamily) || (family == AddressFamily.InterNetwork && IsDualMode);
        }

        #endregion

        #region Public Methods

        /// <devdoc>
        ///    <para>Associates a socket with an end point.</para>
        /// </devdoc>
        public void Bind(EndPoint localEP)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Bind", localEP);

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (localEP == null)
            {
                throw new ArgumentNullException("localEP");
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Bind() localEP:" + localEP.ToString());

            EndPoint endPointSnapshot = localEP;
            IPEndPoint ipSnapshot = localEP as IPEndPoint;

            //
            // for now security is implemented only on IPEndPoint
            // If EndPoint is of other type - unmanaged code permisison is demanded
            //
            if (ipSnapshot != null)
            {
                // Take a snapshot that will make it immutable and not derived.
                ipSnapshot = ipSnapshot.Snapshot();
                endPointSnapshot = RemapIPEndPoint(ipSnapshot);

                // NB: if local port is 0, then winsock will assign some>1024,
                //     so assuming that this is safe. 
            }

            //
            // ask the EndPoint to generate a SocketAddress that we
            // can pass down to winsock
            //
            Internals.SocketAddress socketAddress = CallSerializeCheckDnsEndPoint(endPointSnapshot);
            DoBind(endPointSnapshot, socketAddress);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Bind", "");
        }

        internal void InternalBind(EndPoint localEP)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "InternalBind", localEP);

            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::InternalBind() localEP:" + localEP.ToString());
            GlobalLog.Assert(!(localEP is DnsEndPoint), "Calling InternalBind with a DnsEndPoint, about to get NotImplementedException");

            //
            // ask the EndPoint to generate a SocketAddress that we
            // can pass down to winsock
            //
            EndPoint endPointSnapshot = localEP;
            Internals.SocketAddress socketAddress = SnapshotAndSerialize(ref endPointSnapshot);
            DoBind(endPointSnapshot, socketAddress);

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "InternalBind", "");
        }

        private void DoBind(EndPoint endPointSnapshot, Internals.SocketAddress socketAddress)
        {
            // Mitigation for Blue Screen of Death (Win7, maybe others)
            IPEndPoint ipEndPoint = endPointSnapshot as IPEndPoint;
            if (!OSSupportsIPv4 && ipEndPoint != null && ipEndPoint.Address.IsIPv4MappedToIPv6)
            {
                SocketException socketException = new SocketException((int)SocketError.InvalidArgument);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "DoBind", socketException);
                throw socketException;
            }

            // This may throw ObjectDisposedException.
            SocketError errorCode = SocketPal.Bind(
                _handle,
                socketAddress.Buffer,
                socketAddress.Size);

#if TRAVE
            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Bind() SRC:" + Logging.ObjectToString(LocalEndPoint) + " Interop.Winsock.bind returns errorCode:" + errorCode);
            }
            catch (ObjectDisposedException) { }
#endif

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "DoBind", socketException);
                throw socketException;
            }

            if (m_RightEndPoint == null)
            {
                //
                // save a copy of the EndPoint so we can use it for Create()
                //
                m_RightEndPoint = endPointSnapshot;
            }
        }

        /// <devdoc>
        ///    <para>Establishes a connection to a remote system.</para>
        /// </devdoc>
        public void Connect(EndPoint remoteEP)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (remoteEP == null)
            {
                throw new ArgumentNullException("remoteEP");
            }

            if (_isDisconnected)
            {
                throw new InvalidOperationException(SR.net_sockets_disconnectedConnect);
            }

            if (_isListening)
            {
                throw new InvalidOperationException(SR.net_sockets_mustnotlisten);
            }

            ValidateBlockingMode();
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Connect() DST:" + Logging.ObjectToString(remoteEP));

            DnsEndPoint dnsEP = remoteEP as DnsEndPoint;
            if (dnsEP != null)
            {
                if (dnsEP.AddressFamily != AddressFamily.Unspecified && !CanTryAddressFamily(dnsEP.AddressFamily))
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }

                Connect(dnsEP.Host, dnsEP.Port);
                return;
            }

            //This will check the permissions for connect
            EndPoint endPointSnapshot = remoteEP;
            Internals.SocketAddress socketAddress = CheckCacheRemote(ref endPointSnapshot, true);

            if (!Blocking)
            {
                _nonBlockingConnectRightEndPoint = endPointSnapshot;
                _nonBlockingConnectInProgress = true;
            }

            DoConnect(endPointSnapshot, socketAddress);
        }

        public void Connect(IPAddress address, int port)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Connect", address);

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //if address family isn't the socket address family throw
            if (address == null)
            {
                throw new ArgumentNullException("address");
            }

            if (!TcpValidationHelpers.ValidatePortNumber(port))
            {
                throw new ArgumentOutOfRangeException("port");
            }
            if (!CanTryAddressFamily(address.AddressFamily))
            {
                throw new NotSupportedException(SR.net_invalidversion);
            }

            IPEndPoint remoteEP = new IPEndPoint(address, port);
            Connect(remoteEP);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Connect", null);
        }

        public void Connect(string host, int port)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Connect", host);

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            if (host == null)
            {
                throw new ArgumentNullException("host");
            }
            if (!TcpValidationHelpers.ValidatePortNumber(port))
            {
                throw new ArgumentOutOfRangeException("port");
            }
            if (_addressFamily != AddressFamily.InterNetwork && _addressFamily != AddressFamily.InterNetworkV6)
            {
                throw new NotSupportedException(SR.net_invalidversion);
            }

            IPAddress[] addresses = Dns.GetHostAddressesAsync(host).GetAwaiter().GetResult();
            Connect(addresses, port);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Connect", null);
        }

        public void Connect(IPAddress[] addresses, int port)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Connect", addresses);

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            if (addresses == null)
            {
                throw new ArgumentNullException("addresses");
            }
            if (addresses.Length == 0)
            {
                throw new ArgumentException(SR.net_sockets_invalid_ipaddress_length, "addresses");
            }
            if (!TcpValidationHelpers.ValidatePortNumber(port))
            {
                throw new ArgumentOutOfRangeException("port");
            }
            if (_addressFamily != AddressFamily.InterNetwork && _addressFamily != AddressFamily.InterNetworkV6)
            {
                throw new NotSupportedException(SR.net_invalidversion);
            }

            Exception lastex = null;
            foreach (IPAddress address in addresses)
            {
                if (CanTryAddressFamily(address.AddressFamily))
                {
                    try
                    {
                        Connect(new IPEndPoint(address, port));
                        lastex = null;
                        break;
                    }
                    catch (Exception ex)
                    {
                        if (ExceptionCheck.IsFatal(ex)) throw;
                        lastex = ex;
                    }
                }
            }

            if (lastex != null)
                throw lastex;

            //if we're not connected, then we didn't get a valid ipaddress in the list
            if (!Connected)
            {
                throw new ArgumentException(SR.net_invalidAddressList, "addresses");
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Connect", null);
        }

        public void Close(int timeout)
        {
            if (timeout < -1)
            {
                throw new ArgumentOutOfRangeException("timeout");
            }
            _closeTimeout = timeout;
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Close() timeout = " + _closeTimeout);
            ((IDisposable)this).Dispose();
        }

        /// <devdoc>
        ///    <para>
        ///       Places a socket in a listening state.
        ///    </para>
        /// </devdoc>
        public void Listen(int backlog)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Listen", backlog);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Listen() backlog:" + backlog.ToString());

            // No access permissions are necessary here because
            // the verification is done for Bind

            // This may throw ObjectDisposedException.
            SocketError errorCode = SocketPal.Listen(
                _handle,
                backlog);

#if TRAVE
            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Listen() SRC:" + Logging.ObjectToString(LocalEndPoint) + " Interop.Winsock.listen returns errorCode:" + errorCode);
            }
            catch (ObjectDisposedException) { }
#endif

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "Listen", socketException);
                throw socketException;
            }
            _isListening = true;
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Listen", "");
        }

        /// <devdoc>
        ///    <para>
        ///       Creates a new <see cref='Sockets.Socket'/> instance to handle an incoming
        ///       connection.
        ///    </para>
        /// </devdoc>
        public Socket Accept()
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Accept", "");

            //
            // parameter validation
            //

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            if (m_RightEndPoint == null)
            {
                throw new InvalidOperationException(SR.net_sockets_mustbind);
            }

            if (!_isListening)
            {
                throw new InvalidOperationException(SR.net_sockets_mustlisten);
            }

            if (_isDisconnected)
            {
                throw new InvalidOperationException(SR.net_sockets_disconnectedAccept);
            }

            ValidateBlockingMode();
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Accept() SRC:" + Logging.ObjectToString(LocalEndPoint));

            Internals.SocketAddress socketAddress = IPEndPointExtensions.Serialize(m_RightEndPoint);

            // This may throw ObjectDisposedException.
            SafeCloseSocket acceptedSocketHandle = SocketPal.Accept(
                _handle,
                socketAddress.Buffer,
                ref socketAddress.InternalSize);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (acceptedSocketHandle.IsInvalid)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)SocketPal.GetLastSocketError());
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "Accept", socketException);
                throw socketException;
            }

            Socket socket = CreateAcceptSocket(acceptedSocketHandle, m_RightEndPoint.Create(socketAddress));
            if (s_LoggingEnabled)
            {
                Logging.PrintInfo(Logging.Sockets, socket, SR.Format(SR.net_log_socket_accepted, socket.RemoteEndPoint, socket.LocalEndPoint));
                Logging.Exit(Logging.Sockets, this, "Accept", socket);
            }
            return socket;
        }

        /// <devdoc>
        ///    <para>Sends a data buffer to a connected socket.</para>
        /// </devdoc>
        public int Send(byte[] buffer, int size, SocketFlags socketFlags)
        {
            return Send(buffer, 0, size, socketFlags);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int Send(byte[] buffer, SocketFlags socketFlags)
        {
            return Send(buffer, 0, buffer != null ? buffer.Length : 0, socketFlags);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int Send(byte[] buffer)
        {
            return Send(buffer, 0, buffer != null ? buffer.Length : 0, SocketFlags.None);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int Send(IList<ArraySegment<byte>> buffers)
        {
            return Send(buffers, SocketFlags.None);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int Send(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags)
        {
            SocketError errorCode;
            int bytesTransferred = Send(buffers, socketFlags, out errorCode);
            if (errorCode != SocketError.Success)
            {
                throw new SocketException((int)errorCode);
            }
            return bytesTransferred;
        }

        public int Send(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, out SocketError errorCode)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Send", "");
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            if (buffers == null)
            {
                throw new ArgumentNullException("buffers");
            }

            if (buffers.Count == 0)
            {
                throw new ArgumentException(SR.Format(SR.net_sockets_zerolist, "buffers"), "buffers");
            }

            ValidateBlockingMode();
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Send() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint));

            //make sure we don't let the app mess up the buffer array enough to cause
            //corruption.

            int bytesTransferred;
            errorCode = SocketPal.Send(_handle, buffers, socketFlags, out bytesTransferred);

#if TRAVE
            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Send() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " Interop.Winsock.send returns errorCode:" + errorCode + " bytesTransferred:" + bytesTransferred);
            }
            catch (ObjectDisposedException) { }
#endif

            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled)
                {
                    Logging.Exception(Logging.Sockets, this, "Send", new SocketException((int)errorCode));
                    Logging.Exit(Logging.Sockets, this, "Send", 0);
                }
                return 0;
            }

            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesSent, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsSent);
                    }
                }
            }
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Send", bytesTransferred);
            return bytesTransferred;
        }

        /// <devdoc>
        ///    <para>Sends data to
        ///       a connected socket, starting at the indicated location in the
        ///       data.</para>
        /// </devdoc>
        public int Send(byte[] buffer, int offset, int size, SocketFlags socketFlags)
        {
            SocketError errorCode;
            int bytesTransferred = Send(buffer, offset, size, socketFlags, out errorCode);
            if (errorCode != SocketError.Success)
            {
                throw new SocketException((int)errorCode);
            }
            return bytesTransferred;
        }

        public int Send(byte[] buffer, int offset, int size, SocketFlags socketFlags, out SocketError errorCode)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Send", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }


            errorCode = SocketError.Success;
            ValidateBlockingMode();
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Send() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " size:" + size);

            // This can throw ObjectDisposedException.
            int bytesTransferred;
            errorCode = SocketPal.Send(_handle, buffer, offset, size, socketFlags, out bytesTransferred);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled)
                {
                    Logging.Exception(Logging.Sockets, this, "Send", new SocketException((int)errorCode));
                    Logging.Exit(Logging.Sockets, this, "Send", 0);
                }
                return 0;
            }

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesSent, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsSent);
                    }
                }
            }
#endif //!FEATURE_PAL

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Send() Interop.Winsock.send returns:" + bytesTransferred.ToString());
            GlobalLog.Dump(buffer, offset, bytesTransferred);
            if (s_LoggingEnabled) Logging.Dump(Logging.Sockets, this, "Send", buffer, offset, size);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Send", bytesTransferred);
            return bytesTransferred;
        }

        /// <devdoc>
        ///    <para>Sends data to a specific end point, starting at the indicated location in the
        ///       data.</para>
        /// </devdoc>
        public int SendTo(byte[] buffer, int offset, int size, SocketFlags socketFlags, EndPoint remoteEP)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "SendTo", "");
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (remoteEP == null)
            {
                throw new ArgumentNullException("remoteEP");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }

            ValidateBlockingMode();
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SendTo() SRC:" + Logging.ObjectToString(LocalEndPoint) + " size:" + size + " remoteEP:" + Logging.ObjectToString(remoteEP));

            //That will check ConnectPermission for remoteEP
            EndPoint endPointSnapshot = remoteEP;
            Internals.SocketAddress socketAddress = CheckCacheRemote(ref endPointSnapshot, false);

            // This can throw ObjectDisposedException.
            int bytesTransferred;
            SocketError errorCode = SocketPal.SendTo(_handle, buffer, offset, size, socketFlags, socketAddress.Buffer, socketAddress.Size, out bytesTransferred);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "SendTo", socketException);
                throw socketException;
            }

            if (m_RightEndPoint == null)
            {
                //
                // save a copy of the EndPoint so we can use it for Create()
                //
                m_RightEndPoint = endPointSnapshot;
            }

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesSent, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsSent);
                    }
                }
            }
#endif //!FEATURE_PAL

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SendTo() returning bytesTransferred:" + bytesTransferred.ToString());
            GlobalLog.Dump(buffer, offset, bytesTransferred);
            if (s_LoggingEnabled) Logging.Dump(Logging.Sockets, this, "SendTo", buffer, offset, size);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "SendTo", bytesTransferred);
            return bytesTransferred;
        }

        /// <devdoc>
        ///    <para>Sends data to a specific end point, starting at the indicated location in the data.</para>
        /// </devdoc>
        public int SendTo(byte[] buffer, int size, SocketFlags socketFlags, EndPoint remoteEP)
        {
            return SendTo(buffer, 0, size, socketFlags, remoteEP);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int SendTo(byte[] buffer, SocketFlags socketFlags, EndPoint remoteEP)
        {
            return SendTo(buffer, 0, buffer != null ? buffer.Length : 0, socketFlags, remoteEP);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int SendTo(byte[] buffer, EndPoint remoteEP)
        {
            return SendTo(buffer, 0, buffer != null ? buffer.Length : 0, SocketFlags.None, remoteEP);
        }

        /// <devdoc>
        ///    <para>Receives data from a connected socket.</para>
        /// </devdoc>
        public int Receive(byte[] buffer, int size, SocketFlags socketFlags)
        {
            return Receive(buffer, 0, size, socketFlags);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int Receive(byte[] buffer, SocketFlags socketFlags)
        {
            return Receive(buffer, 0, buffer != null ? buffer.Length : 0, socketFlags);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int Receive(byte[] buffer)
        {
            return Receive(buffer, 0, buffer != null ? buffer.Length : 0, SocketFlags.None);
        }

        /// <devdoc>
        ///    <para>Receives data from a connected socket into a specific location of the receive
        ///       buffer.</para>
        /// </devdoc>
        public int Receive(byte[] buffer, int offset, int size, SocketFlags socketFlags)
        {
            SocketError errorCode;
            int bytesTransferred = Receive(buffer, offset, size, socketFlags, out errorCode);
            if (errorCode != SocketError.Success)
            {
                throw new SocketException((int)errorCode);
            }
            return bytesTransferred;
        }

        public int Receive(byte[] buffer, int offset, int size, SocketFlags socketFlags, out SocketError errorCode)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Receive", "");
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //

            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }


            ValidateBlockingMode();
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Receive() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " size:" + size);

            int bytesTransferred;
            errorCode = SocketPal.Receive(_handle, buffer, offset, size, socketFlags, out bytesTransferred);

            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled)
                {
                    Logging.Exception(Logging.Sockets, this, "Receive", new SocketException((int)errorCode));
                    Logging.Exit(Logging.Sockets, this, "Receive", 0);
                }
                return 0;
            }

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                bool peek = ((int)socketFlags & (int)SocketFlags.Peek) != 0;

                if (bytesTransferred > 0 && !peek)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesReceived, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsReceived);
                    }
                }
            }
#endif //!FEATURE_PAL

#if TRAVE
            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Receive() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " bytesTransferred:" + bytesTransferred);
            }
            catch (ObjectDisposedException) { }
#endif
            GlobalLog.Dump(buffer, offset, bytesTransferred);

            if (s_LoggingEnabled) Logging.Dump(Logging.Sockets, this, "Receive", buffer, offset, bytesTransferred);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Receive", bytesTransferred);

            return bytesTransferred;
        }

        public int Receive(IList<ArraySegment<byte>> buffers)
        {
            return Receive(buffers, SocketFlags.None);
        }

        public int Receive(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags)
        {
            SocketError errorCode;
            int bytesTransferred = Receive(buffers, socketFlags, out errorCode);
            if (errorCode != SocketError.Success)
            {
                throw new SocketException((int)errorCode);
            }
            return bytesTransferred;
        }

        public int Receive(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, out SocketError errorCode)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Receive", "");
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            if (buffers == null)
            {
                throw new ArgumentNullException("buffers");
            }

            if (buffers.Count == 0)
            {
                throw new ArgumentException(SR.Format(SR.net_sockets_zerolist, "buffers"), "buffers");
            }


            ValidateBlockingMode();
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Receive() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint));

            //make sure we don't let the app mess up the buffer array enough to cause
            //corruption.
            errorCode = SocketError.Success;

            int bytesTransferred;
            errorCode = SocketPal.Receive(_handle, buffers, ref socketFlags, out bytesTransferred);

#if TRAVE
            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Receive() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " Interop.Winsock.send returns errorCode:" + errorCode + " bytesTransferred:" + bytesTransferred);
            }
            catch (ObjectDisposedException) { }
#endif

            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled)
                {
                    Logging.Exception(Logging.Sockets, this, "Receive", new SocketException((int)errorCode));
                    Logging.Exit(Logging.Sockets, this, "Receive", 0);
                }
                return 0;
            }



#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                bool peek = ((int)socketFlags & (int)SocketFlags.Peek) != 0;

                if (bytesTransferred > 0 && !peek)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesReceived, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsReceived);
                    }
                }
            }
#endif //!FEATURE_PAL

#if TRAVE
            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Receive() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " bytesTransferred:" + bytesTransferred);
            }
            catch (ObjectDisposedException) { }
#endif

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Receive", bytesTransferred);

            return bytesTransferred;
        }

        /// <devdoc>
        ///    <para>Receives a datagram into a specific location in the data buffer and stores
        ///       the end point.</para>
        /// </devdoc>
        public int ReceiveMessageFrom(byte[] buffer, int offset, int size, ref SocketFlags socketFlags, ref EndPoint remoteEP, out IPPacketInformation ipPacketInformation)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "ReceiveMessageFrom", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (remoteEP == null)
            {
                throw new ArgumentNullException("remoteEP");
            }
            if (!CanTryAddressFamily(remoteEP.AddressFamily))
            {
                throw new ArgumentException(SR.Format(SR.net_InvalidEndPointAddressFamily,
                    remoteEP.AddressFamily, _addressFamily), "remoteEP");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }
            if (m_RightEndPoint == null)
            {
                throw new InvalidOperationException(SR.net_sockets_mustbind);
            }


            ValidateBlockingMode();

            // We don't do a CAS demand here because the contents of remoteEP aren't used by
            // WSARecvMsg; all that matters is that we generate a unique-to-this-call SocketAddress
            // with the right address family
            EndPoint endPointSnapshot = remoteEP;
            Internals.SocketAddress socketAddress = SnapshotAndSerialize(ref endPointSnapshot);

            // save a copy of the original EndPoint
            Internals.SocketAddress socketAddressOriginal = IPEndPointExtensions.Serialize(endPointSnapshot);

            //setup structure

            SetReceivingPacketInformation();

            Internals.SocketAddress receiveAddress;
            int bytesTransferred;
            SocketError errorCode = SocketPal.ReceiveMessageFrom(this, _handle, buffer, offset, size, ref socketFlags, socketAddress, out receiveAddress, out ipPacketInformation, out bytesTransferred);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success && errorCode != SocketError.MessageSize)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "ReceiveMessageFrom", socketException);
                throw socketException;
            }

            if (!socketAddressOriginal.Equals(receiveAddress))
            {
                try
                {
                    remoteEP = endPointSnapshot.Create(receiveAddress);
                }
                catch
                {
                }
                if (m_RightEndPoint == null)
                {
                    //
                    // save a copy of the EndPoint so we can use it for Create()
                    //
                    m_RightEndPoint = endPointSnapshot;
                }
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "ReceiveMessageFrom", errorCode);
            return bytesTransferred;
        }

        /// <devdoc>
        ///    <para>Receives a datagram into a specific location in the data buffer and stores
        ///       the end point.</para>
        /// </devdoc>
        public int ReceiveFrom(byte[] buffer, int offset, int size, SocketFlags socketFlags, ref EndPoint remoteEP)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "ReceiveFrom", "");
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (remoteEP == null)
            {
                throw new ArgumentNullException("remoteEP");
            }
            if (!CanTryAddressFamily(remoteEP.AddressFamily))
            {
                throw new ArgumentException(SR.Format(SR.net_InvalidEndPointAddressFamily,
                    remoteEP.AddressFamily, _addressFamily), "remoteEP");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }
            if (m_RightEndPoint == null)
            {
                throw new InvalidOperationException(SR.net_sockets_mustbind);
            }


            ValidateBlockingMode();
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::ReceiveFrom() SRC:" + Logging.ObjectToString(LocalEndPoint) + " size:" + size + " remoteEP:" + remoteEP.ToString());

            // We don't do a CAS demand here because the contents of remoteEP aren't used by
            // WSARecvFrom; all that matters is that we generate a unique-to-this-call SocketAddress
            // with the right address family
            EndPoint endPointSnapshot = remoteEP;
            Internals.SocketAddress socketAddress = SnapshotAndSerialize(ref endPointSnapshot);
            Internals.SocketAddress socketAddressOriginal = IPEndPointExtensions.Serialize(endPointSnapshot);

            // This can throw ObjectDisposedException.
            int bytesTransferred;
            SocketError errorCode = SocketPal.ReceiveFrom(_handle, buffer, offset, size, socketFlags, socketAddress.Buffer, ref socketAddress.InternalSize, out bytesTransferred);

            // If the native call fails we'll throw a SocketException.
            // Must do this immediately after the native call so that the SocketException() constructor can pick up the error code.
            SocketException socketException = null;
            if (errorCode != SocketError.Success)
            {
                socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "ReceiveFrom", socketException);

                if (socketException.SocketErrorCode != SocketError.MessageSize)
                {
                    throw socketException;
                }
            }

            if (!socketAddressOriginal.Equals(socketAddress))
            {
                try
                {
                    remoteEP = endPointSnapshot.Create(socketAddress);
                }
                catch
                {
                }
                if (m_RightEndPoint == null)
                {
                    //
                    // save a copy of the EndPoint so we can use it for Create()
                    //
                    m_RightEndPoint = endPointSnapshot;
                }
            }

            if (socketException != null)
            {
                throw socketException;
            }


#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesReceived, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsReceived);
                    }
                }
            }
#endif //!FEATURE_PAL
            GlobalLog.Dump(buffer, offset, bytesTransferred);

            if (s_LoggingEnabled) Logging.Dump(Logging.Sockets, this, "ReceiveFrom", buffer, offset, size);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "ReceiveFrom", bytesTransferred);
            return bytesTransferred;
        }

        /// <devdoc>
        ///    <para>Receives a datagram and stores the source end point.</para>
        /// </devdoc>
        public int ReceiveFrom(byte[] buffer, int size, SocketFlags socketFlags, ref EndPoint remoteEP)
        {
            return ReceiveFrom(buffer, 0, size, socketFlags, ref remoteEP);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int ReceiveFrom(byte[] buffer, SocketFlags socketFlags, ref EndPoint remoteEP)
        {
            return ReceiveFrom(buffer, 0, buffer != null ? buffer.Length : 0, socketFlags, ref remoteEP);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int ReceiveFrom(byte[] buffer, ref EndPoint remoteEP)
        {
            return ReceiveFrom(buffer, 0, buffer != null ? buffer.Length : 0, SocketFlags.None, ref remoteEP);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int IOControl(int ioControlCode, byte[] optionInValue, byte[] optionOutValue)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            int realOptionLength = 0;

            // This can throw ObjectDisposedException.
            SocketError errorCode = SocketPal.Ioctl(_handle, ioControlCode, optionInValue, optionOutValue, out realOptionLength);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::IOControl() Interop.Winsock.WSAIoctl returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "IOControl", socketException);
                throw socketException;
            }

            return realOptionLength;
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public int IOControl(IOControlCode ioControlCode, byte[] optionInValue, byte[] optionOutValue)
        {
            return IOControl(unchecked((int)ioControlCode), optionInValue, optionOutValue);
        }

        internal int IOControl(IOControlCode ioControlCode,
                                    IntPtr optionInValue,
                                    int inValueSize,
                                    IntPtr optionOutValue,
                                    int outValueSize)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            int realOptionLength = 0;

            // This can throw ObjectDisposedException.
            SocketError errorCode = SocketPal.IoctlInternal(_handle, ioControlCode, optionInValue, inValueSize, optionOutValue, outValueSize, out realOptionLength);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::IOControl() Interop.Winsock.WSAIoctl returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "IOControl", socketException);
                throw socketException;
            }

            return realOptionLength;
        }

        public void SetIPProtectionLevel(IPProtectionLevel level)
        {
            if (level == IPProtectionLevel.Unspecified)
            {
                throw new ArgumentException(SR.net_sockets_invalid_optionValue_all, "level");
            }

            if (_addressFamily == AddressFamily.InterNetworkV6)
            {
                SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPProtectionLevel, (int)level);
            }
            else if (_addressFamily == AddressFamily.InterNetwork)
            {
                SetSocketOption(SocketOptionLevel.IP, SocketOptionName.IPProtectionLevel, (int)level);
            }
            else
            {
                throw new NotSupportedException(SR.net_invalidversion);
            }
        }

        /// <devdoc>
        ///    <para>
        ///       Sets the specified option to the specified value.
        ///    </para>
        /// </devdoc>
        public void SetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, int optionValue)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            CheckSetOptionPermissions(optionLevel, optionName);
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetSocketOption(): optionLevel:" + optionLevel.ToString() + " optionName:" + optionName.ToString() + " optionValue:" + optionValue.ToString());
            SetSocketOption(optionLevel, optionName, optionValue, false);
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public void SetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            CheckSetOptionPermissions(optionLevel, optionName);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetSocketOption(): optionLevel:" + optionLevel.ToString() + " optionName:" + optionName.ToString() + " optionValue:" + optionValue.ToString());

            // This can throw ObjectDisposedException.
            SocketError errorCode = SocketPal.SetSockOpt(_handle, optionLevel, optionName, optionValue);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetSocketOption() Interop.Winsock.setsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "SetSocketOption", socketException);
                throw socketException;
            }
        }

        /// <devdoc>
        ///    <para>Sets the specified option to the specified value.</para>
        /// </devdoc>

        public void SetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, bool optionValue)
        {
            SetSocketOption(optionLevel, optionName, (optionValue ? 1 : 0));
        }

        /// <devdoc>
        ///    <para>Sets the specified option to the specified value.</para>
        /// </devdoc>
        public void SetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, object optionValue)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (optionValue == null)
            {
                throw new ArgumentNullException("optionValue");
            }

            CheckSetOptionPermissions(optionLevel, optionName);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetSocketOption(): optionLevel:" + optionLevel.ToString() + " optionName:" + optionName.ToString() + " optionValue:" + optionValue.ToString());

            if (optionLevel == SocketOptionLevel.Socket && optionName == SocketOptionName.Linger)
            {
                LingerOption lingerOption = optionValue as LingerOption;
                if (lingerOption == null)
                {
                    throw new ArgumentException(SR.Format(SR.net_sockets_invalid_optionValue, "LingerOption"), "optionValue");
                }
                if (lingerOption.LingerTime < 0 || lingerOption.LingerTime > (int)UInt16.MaxValue)
                {
                    throw new ArgumentException(SR.Format(SR.ArgumentOutOfRange_Bounds_Lower_Upper, 0, (int)UInt16.MaxValue), "optionValue.LingerTime");
                }
                setLingerOption(lingerOption);
            }
            else if (optionLevel == SocketOptionLevel.IP && (optionName == SocketOptionName.AddMembership || optionName == SocketOptionName.DropMembership))
            {
                MulticastOption multicastOption = optionValue as MulticastOption;
                if (multicastOption == null)
                {
                    throw new ArgumentException(SR.Format(SR.net_sockets_invalid_optionValue, "MulticastOption"), "optionValue");
                }
                setMulticastOption(optionName, multicastOption);
            }
            //
            // IPv6 Changes: Handle IPv6 Multicast Add / Drop
            //
            else if (optionLevel == SocketOptionLevel.IPv6 && (optionName == SocketOptionName.AddMembership || optionName == SocketOptionName.DropMembership))
            {
                IPv6MulticastOption multicastOption = optionValue as IPv6MulticastOption;
                if (multicastOption == null)
                {
                    throw new ArgumentException(SR.Format(SR.net_sockets_invalid_optionValue, "IPv6MulticastOption"), "optionValue");
                }
                setIPv6MulticastOption(optionName, multicastOption);
            }
            else
            {
                throw new ArgumentException(SR.net_sockets_invalid_optionValue_all, "optionValue");
            }
        }

        /// <devdoc>
        ///    <para>
        ///       Gets the value of a socket option.
        ///    </para>
        /// </devdoc>
        public object GetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            if (optionLevel == SocketOptionLevel.Socket && optionName == SocketOptionName.Linger)
            {
                return getLingerOpt();
            }
            else if (optionLevel == SocketOptionLevel.IP && (optionName == SocketOptionName.AddMembership || optionName == SocketOptionName.DropMembership))
            {
                return getMulticastOpt(optionName);
            }
            //
            // Handle IPv6 case
            //
            else if (optionLevel == SocketOptionLevel.IPv6 && (optionName == SocketOptionName.AddMembership || optionName == SocketOptionName.DropMembership))
            {
                return getIPv6MulticastOpt(optionName);
            }

            int optionValue = 0;

            // This can throw ObjectDisposedException.
            SocketError errorCode = SocketPal.GetSockOpt(
                _handle,
                optionLevel,
                optionName,
                out optionValue);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::GetSocketOption() Interop.Winsock.getsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "GetSocketOption", socketException);
                throw socketException;
            }

            return optionValue;
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public void GetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, byte[] optionValue)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            int optionLength = optionValue != null ? optionValue.Length : 0;

            // This can throw ObjectDisposedException.
            SocketError errorCode = SocketPal.GetSockOpt(
                _handle,
                optionLevel,
                optionName,
                optionValue,
                ref optionLength);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::GetSocketOption() Interop.Winsock.getsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "GetSocketOption", socketException);
                throw socketException;
            }
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public byte[] GetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, int optionLength)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            byte[] optionValue = new byte[optionLength];
            int realOptionLength = optionLength;

            // This can throw ObjectDisposedException.
            SocketError errorCode = SocketPal.GetSockOpt(
                _handle,
                optionLevel,
                optionName,
                optionValue,
                ref realOptionLength);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::GetSocketOption() Interop.Winsock.getsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "GetSocketOption", socketException);
                throw socketException;
            }

            if (optionLength != realOptionLength)
            {
                byte[] newOptionValue = new byte[realOptionLength];
                Buffer.BlockCopy(optionValue, 0, newOptionValue, 0, realOptionLength);
                optionValue = newOptionValue;
            }

            return optionValue;
        }

        /// <devdoc>
        ///    <para>
        ///       Determines the status of the socket.
        ///    </para>
        /// </devdoc>
        public bool Poll(int microSeconds, SelectMode mode)
        {
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            
            bool status;
            SocketError errorCode = SocketPal.Poll(_handle, microSeconds, mode, out status);
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Poll() Interop.Winsock.select returns socketCount:" + (int)errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode == SocketError.SocketError)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)SocketPal.GetLastSocketError());
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "Poll", socketException);
                throw socketException;
            }

            return status;
        }

        /// <devdoc>
        ///    <para>Determines the status of a socket.</para>
        /// </devdoc>
        public static void Select(IList checkRead, IList checkWrite, IList checkError, int microSeconds)
        {
            // parameter validation
            if ((checkRead == null || checkRead.Count == 0) && (checkWrite == null || checkWrite.Count == 0) && (checkError == null || checkError.Count == 0))
            {
                throw new ArgumentNullException(SR.net_sockets_empty_select);
            }
            const int MaxSelect = 65536;
            if (checkRead != null && checkRead.Count > MaxSelect)
            {
                throw new ArgumentOutOfRangeException("checkRead", SR.Format(SR.net_sockets_toolarge_select, "checkRead", MaxSelect.ToString(NumberFormatInfo.CurrentInfo)));
            }
            if (checkWrite != null && checkWrite.Count > MaxSelect)
            {
                throw new ArgumentOutOfRangeException("checkWrite", SR.Format(SR.net_sockets_toolarge_select, "checkWrite", MaxSelect.ToString(NumberFormatInfo.CurrentInfo)));
            }
            if (checkError != null && checkError.Count > MaxSelect)
            {
                throw new ArgumentOutOfRangeException("checkError", SR.Format(SR.net_sockets_toolarge_select, "checkError", MaxSelect.ToString(NumberFormatInfo.CurrentInfo)));
            }

            SocketError errorCode = SocketPal.Select(checkRead, checkWrite, checkError, microSeconds);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode == SocketError.SocketError)
            {
                throw new SocketException((int)SocketPal.GetLastSocketError());
            }
        }

        /*++

        Routine Description:

           BeginConnect - Does a async winsock connect, by calling
           WSAEventSelect to enable Connect Events to signal an event and
           wake up a callback which involkes a callback.

            So note: This routine may go pending at which time,
            but any case the callback Delegate will be called upon completion

        Arguments:

           remoteEP - status line that we wish to parse
           Callback - Async Callback Delegate that is called upon Async Completion
           State - State used to track callback, set by caller, not required

        Return Value:

           IAsyncResult - Async result used to retreive result

        --*/
        public IAsyncResult BeginConnect(EndPoint remoteEP, AsyncCallback callback, object state)
        {
            //
            //  parameter validation
            //
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginConnect", remoteEP);

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            if (remoteEP == null)
            {
                throw new ArgumentNullException("remoteEP");
            }

            if (_isListening)
            {
                throw new InvalidOperationException(SR.net_sockets_mustnotlisten);
            }

            DnsEndPoint dnsEP = remoteEP as DnsEndPoint;
            if (dnsEP != null)
            {
                if (dnsEP.AddressFamily != AddressFamily.Unspecified && !CanTryAddressFamily(dnsEP.AddressFamily))
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }

                return BeginConnect(dnsEP.Host, dnsEP.Port, callback, state);
            }

            return BeginConnectEx(remoteEP, true, callback, state);
        }

        internal IAsyncResult UnsafeBeginConnect(EndPoint remoteEP, AsyncCallback callback, object state)
        {
            return BeginConnectEx(remoteEP, false, callback, state);
        }

        public IAsyncResult BeginConnect(string host, int port, AsyncCallback requestCallback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginConnect", host);

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            if (host == null)
            {
                throw new ArgumentNullException("host");
            }
            if (!TcpValidationHelpers.ValidatePortNumber(port))
            {
                throw new ArgumentOutOfRangeException("port");
            }
            if (_addressFamily != AddressFamily.InterNetwork && _addressFamily != AddressFamily.InterNetworkV6)
            {
                throw new NotSupportedException(SR.net_invalidversion);
            }

            if (_isListening)
            {
                throw new InvalidOperationException(SR.net_sockets_mustnotlisten);
            }

            // Here, want to flow the context.  No need to lock.
            MultipleAddressConnectAsyncResult result = new MultipleAddressConnectAsyncResult(null, port, this, state, requestCallback);
            result.StartPostingAsyncOp(false);

            IAsyncResult dnsResult = DnsAPMExtensions.BeginGetHostAddresses(host, new AsyncCallback(DnsCallback), result);
            if (dnsResult.CompletedSynchronously)
            {
                if (DoDnsCallback(dnsResult, result))
                {
                    result.InvokeCallback();
                }
            }

            // Done posting.
            result.FinishPostingAsyncOp(ref Caches.ConnectClosureCache);

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginConnect", result);
            return result;
        }

        public IAsyncResult BeginConnect(IPAddress address, int port, AsyncCallback requestCallback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginConnect", address);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            if (address == null)
            {
                throw new ArgumentNullException("address");
            }
            if (!TcpValidationHelpers.ValidatePortNumber(port))
            {
                throw new ArgumentOutOfRangeException("port");
            }
            //if address family isn't the socket address family throw
            if (!CanTryAddressFamily(address.AddressFamily))
            {
                throw new NotSupportedException(SR.net_invalidversion);
            }

            IAsyncResult result = BeginConnect(new IPEndPoint(address, port), requestCallback, state);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginConnect", result);
            return result;
        }

        public IAsyncResult BeginConnect(IPAddress[] addresses, int port, AsyncCallback requestCallback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginConnect", addresses);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            if (addresses == null)
            {
                throw new ArgumentNullException("addresses");
            }
            if (addresses.Length == 0)
            {
                throw new ArgumentException(SR.net_invalidAddressList, "addresses");
            }
            if (!TcpValidationHelpers.ValidatePortNumber(port))
            {
                throw new ArgumentOutOfRangeException("port");
            }
            if (_addressFamily != AddressFamily.InterNetwork && _addressFamily != AddressFamily.InterNetworkV6)
            {
                throw new NotSupportedException(SR.net_invalidversion);
            }

            if (_isListening)
            {
                throw new InvalidOperationException(SR.net_sockets_mustnotlisten);
            }

            // Set up the result to capture the context.  No need for a lock.
            MultipleAddressConnectAsyncResult result = new MultipleAddressConnectAsyncResult(addresses, port, this, state, requestCallback);
            result.StartPostingAsyncOp(false);

            if (DoMultipleAddressConnectCallback(PostOneBeginConnect(result), result))
            {
                // if it completes synchronously, invoke the callback from here
                result.InvokeCallback();
            }

            // Finished posting async op.  Possibly will call callback.
            result.FinishPostingAsyncOp(ref Caches.ConnectClosureCache);

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginConnect", result);
            return result;
        }

        // Supports DisconnectEx - this provides completion port IO and support for
        //disconnect and reconnects
        public IAsyncResult BeginDisconnect(bool reuseSocket, AsyncCallback callback, object state)
        {
            // Start context-flowing op.  No need to lock - we don't use the context till the callback.
            DisconnectOverlappedAsyncResult asyncResult = new DisconnectOverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Post the disconnect.
            DoBeginDisconnect(reuseSocket, asyncResult);

            // Finish flowing (or call the callback), and return.
            asyncResult.FinishPostingAsyncOp();
            return asyncResult;
        }

        private void DoBeginDisconnect(bool reuseSocket, DisconnectOverlappedAsyncResult asyncResult)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginDisconnect", null);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginDisconnect() ");

#if FEATURE_PAL
            throw new PlatformNotSupportedException(SR.WinXPRequired);
#endif

            SocketError errorCode = SocketPal.DisconnectAsync(this, _handle, reuseSocket, asyncResult);

            if (errorCode == SocketError.Success)
            {
                SetToDisconnected();
                m_RemoteEndPoint = null;
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginDisconnect() Interop.Winsock.DisConnectEx returns:" + errorCode.ToString());

            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);

            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginDisconnect", socketException);
                throw socketException;
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginDisconnect() returning AsyncResult:" + Logging.HashString(asyncResult));
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginDisconnect", asyncResult);
        }

        // Supports DisconnectEx - this provides support for disconnect and reconnects
        public void Disconnect(bool reuseSocket)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Disconnect", null);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

#if FEATURE_PAL
            throw new PlatformNotSupportedException(SR.WinXPRequired);
#endif // FEATURE_PAL


            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Disconnect() ");

            SocketError errorCode = SocketPal.Disconnect(this, _handle, reuseSocket);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Disconnect() Interop.Winsock.DisConnectEx returns:" + errorCode.ToString());


            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "Disconnect", socketException);
                throw socketException;
            }

            SetToDisconnected();
            m_RemoteEndPoint = null;

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Disconnect", null);
        }

        /*++

        Routine Description:

           EndConnect - Called after receiving callback from BeginConnect,
            in order to retrive the result of async call

        Arguments:

           AsyncResult - the AsyncResult Returned fron BeginConnect call

        Return Value:

           int - Return code from aync Connect, 0 for success, SocketError.NotConnected otherwise

        --*/
        public void EndConnect(IAsyncResult asyncResult)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndConnect", asyncResult);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }

            LazyAsyncResult castedAsyncResult = null;
            EndPoint remoteEndPoint = null;
            ConnectOverlappedAsyncResult coar;
            MultipleAddressConnectAsyncResult macar;
            ConnectAsyncResult car;

            coar = asyncResult as ConnectOverlappedAsyncResult;
            if (coar == null)
            {
                macar = asyncResult as MultipleAddressConnectAsyncResult;
                if (macar == null)
                {
                    car = asyncResult as ConnectAsyncResult;
                    if (car != null)
                    {
                        remoteEndPoint = car.RemoteEndPoint;
                        castedAsyncResult = car;
                    }
                }
                else
                {
                    remoteEndPoint = macar.RemoteEndPoint;
                    castedAsyncResult = macar;
                }
            }
            else
            {
                remoteEndPoint = coar.RemoteEndPoint;
                castedAsyncResult = coar;
            }

            if (castedAsyncResult == null || castedAsyncResult.AsyncObject != this)
            {
                throw new ArgumentException(SR.net_io_invalidasyncresult, "asyncResult");
            }
            if (castedAsyncResult.EndCalled)
            {
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidendcall, "EndConnect"));
            }

            castedAsyncResult.InternalWaitForCompletion();
            castedAsyncResult.EndCalled = true;
            _acceptQueueOrConnectResult = null;

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndConnect() asyncResult:" + Logging.HashString(asyncResult));

            if (castedAsyncResult.Result is Exception)
            {
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "EndConnect", (Exception)castedAsyncResult.Result);
                throw (Exception)castedAsyncResult.Result;
            }
            if ((SocketError)castedAsyncResult.ErrorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = SocketExceptionFactory.CreateSocketException(castedAsyncResult.ErrorCode, remoteEndPoint);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "EndConnect", socketException);
                throw socketException;
            }
            if (s_LoggingEnabled)
            {
                Logging.PrintInfo(Logging.Sockets, this, SR.Format(SR.net_log_socket_connected, LocalEndPoint, RemoteEndPoint));
                Logging.Exit(Logging.Sockets, this, "EndConnect", "");
            }
        }

        public void EndDisconnect(IAsyncResult asyncResult)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndDisconnect", asyncResult);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

#if FEATURE_PAL
            throw new PlatformNotSupportedException(SR.WinNTRequired);
#endif // FEATURE_PAL

            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }


            //get async result and check for errors
            LazyAsyncResult castedAsyncResult = asyncResult as LazyAsyncResult;
            if (castedAsyncResult == null || castedAsyncResult.AsyncObject != this)
            {
                throw new ArgumentException(SR.net_io_invalidasyncresult, "asyncResult");
            }
            if (castedAsyncResult.EndCalled)
            {
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidendcall, "EndDisconnect"));
            }

            //wait for completion if it hasn't occured
            castedAsyncResult.InternalWaitForCompletion();
            castedAsyncResult.EndCalled = true;


            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndDisconnect()");

            //
            // if the asynchronous native call failed asynchronously
            // we'll throw a SocketException
            //
            if ((SocketError)castedAsyncResult.ErrorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException(castedAsyncResult.ErrorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "EndDisconnect", socketException);
                throw socketException;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "EndDisconnect", null);
            return;
        }

        /*++

        Routine Description:

           BeginSend - Async implimentation of Send call, mirrored after BeginReceive
           This routine may go pending at which time,
           but any case the callback Delegate will be called upon completion

        Arguments:

           WriteBuffer - status line that we wish to parse
           Index - Offset into WriteBuffer to begin sending from
           Size - Size of Buffer to transmit
           Callback - Delegate function that holds callback, called on completeion of I/O
           State - State used to track callback, set by caller, not required

        Return Value:

           IAsyncResult - Async result used to retreive result

        --*/
        public IAsyncResult BeginSend(byte[] buffer, int offset, int size, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            SocketError errorCode;
            IAsyncResult result = BeginSend(buffer, offset, size, socketFlags, out errorCode, callback, state);
            if (errorCode != SocketError.Success && errorCode != SocketError.IOPending)
            {
                throw new SocketException((int)errorCode);
            }
            return result;
        }

        public IAsyncResult BeginSend(byte[] buffer, int offset, int size, SocketFlags socketFlags, out SocketError errorCode, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginSend", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }

            // We need to flow the context here.  But we don't need to lock the context - we don't use it until the callback.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Run the send with this asyncResult.
            errorCode = DoBeginSend(buffer, offset, size, socketFlags, asyncResult);

            if (errorCode != SocketError.Success && errorCode != SocketError.IOPending)
            {
                asyncResult = null;
            }
            else
            {
                // We're not throwing, so finish the async op posting code so we can return to the user.
                // If the operation already finished, the callback will be called from here.
                asyncResult.FinishPostingAsyncOp(ref Caches.SendClosureCache);
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginSend", asyncResult);
            return asyncResult;
        }

        internal IAsyncResult UnsafeBeginSend(byte[] buffer, int offset, int size, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "UnsafeBeginSend", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            // No need to flow the context.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);

            SocketError errorCode = DoBeginSend(buffer, offset, size, socketFlags, asyncResult);
            if (errorCode != SocketError.Success && errorCode != SocketError.IOPending)
            {
                throw new SocketException((int)errorCode);
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "UnsafeBeginSend", asyncResult);
            return asyncResult;
        }

        private SocketError DoBeginSend(byte[] buffer, int offset, int size, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginSend() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " size:" + size.ToString());

            // Guarantee to call CheckAsyncCallOverlappedResult if we call SetUnamangedStructures with a cache in order to
            // avoid a Socket leak in case of error.
            SocketError errorCode = SocketError.SocketError;
            try
            {
                //
                // Get the Send going.
                //
                GlobalLog.Print("BeginSend: asyncResult:" + Logging.HashString(asyncResult) + " size:" + size.ToString());

                errorCode = SocketPal.SendAsync(_handle, buffer, offset, size, socketFlags, asyncResult);

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginSend() Interop.Winsock.WSASend returns:" + errorCode.ToString() + " size:" + size.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
            }
            finally
            {
                errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);
            }

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginSend", new SocketException((int)errorCode));
            }
            return errorCode;
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public IAsyncResult BeginSend(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            SocketError errorCode;
            IAsyncResult result = BeginSend(buffers, socketFlags, out errorCode, callback, state);
            if (errorCode != SocketError.Success && errorCode != SocketError.IOPending)
            {
                throw new SocketException((int)errorCode);
            }
            return result;
        }

        public IAsyncResult BeginSend(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, out SocketError errorCode, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginSend", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            //
            // parameter validation
            //
            if (buffers == null)
            {
                throw new ArgumentNullException("buffers");
            }

            if (buffers.Count == 0)
            {
                throw new ArgumentException(SR.Format(SR.net_sockets_zerolist, "buffers"), "buffers");
            }

            // We need to flow the context here.  But we don't need to lock the context - we don't use it until the callback.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Run the send with this asyncResult.
            errorCode = DoBeginSend(buffers, socketFlags, asyncResult);

            // We're not throwing, so finish the async op posting code so we can return to the user.
            // If the operation already finished, the callback will be called from here.
            asyncResult.FinishPostingAsyncOp(ref Caches.SendClosureCache);

            if (errorCode != SocketError.Success && errorCode != SocketError.IOPending)
            {
                asyncResult = null;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginSend", asyncResult);
            return asyncResult;
        }

        private SocketError DoBeginSend(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginSend() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " buffers:" + buffers);

            // Guarantee to call CheckAsyncCallOverlappedResult if we call SetUnamangedStructures with a cache in order to
            // avoid a Socket leak in case of error.
            SocketError errorCode = SocketError.SocketError;
            try
            {
                GlobalLog.Print("BeginSend: asyncResult:" + Logging.HashString(asyncResult));

                errorCode = SocketPal.SendAsync(_handle, buffers, socketFlags, asyncResult);

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginSend() Interop.Winsock.WSASend returns:" + errorCode.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
            }
            finally
            {
                errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);
            }

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginSend", new SocketException((int)errorCode));
            }
            return errorCode;
        }

        /*++

        Routine Description:

           EndSend -  Called by user code after I/O is done or the user wants to wait.
                        until Async completion, needed to retrieve error result from call

        Arguments:

           AsyncResult - the AsyncResult Returned fron BeginSend call

        Return Value:

           int - Number of bytes transferred

        --*/
        public int EndSend(IAsyncResult asyncResult)
        {
            SocketError errorCode;
            int bytesTransferred = EndSend(asyncResult, out errorCode);
            if (errorCode != SocketError.Success)
            {
                throw new SocketException((int)errorCode);
            }
            return bytesTransferred;
        }

        public int EndSend(IAsyncResult asyncResult, out SocketError errorCode)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndSend", asyncResult);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }
            OverlappedAsyncResult castedAsyncResult = asyncResult as OverlappedAsyncResult;
            if (castedAsyncResult == null || castedAsyncResult.AsyncObject != this)
            {
                throw new ArgumentException(SR.net_io_invalidasyncresult, "asyncResult");
            }
            if (castedAsyncResult.EndCalled)
            {
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidendcall, "EndSend"));
            }

            int bytesTransferred = (int)castedAsyncResult.InternalWaitForCompletion();
            castedAsyncResult.EndCalled = true;

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesSent, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsSent);
                    }
                }
            }
#endif //!FEATURE_PAL
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndSend() bytesTransferred:" + bytesTransferred.ToString());

            //
            // if the asynchronous native call failed asynchronously
            // we'll throw a SocketException
            //
            errorCode = (SocketError)castedAsyncResult.ErrorCode;
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled)
                {
                    Logging.Exception(Logging.Sockets, this, "EndSend", new SocketException((int)errorCode));
                    Logging.Exit(Logging.Sockets, this, "EndSend", 0);
                }
                return 0;
            }
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "EndSend", bytesTransferred);
            return bytesTransferred;
        }

        /*++

        Routine Description:

           BeginSendTo - Async implimentation of SendTo,

           This routine may go pending at which time,
           but any case the callback Delegate will be called upon completion

        Arguments:

           WriteBuffer - Buffer to transmit
           Index - Offset into WriteBuffer to begin sending from
           Size - Size of Buffer to transmit
           Flags - Specific Socket flags to pass to winsock
           remoteEP - EndPoint to transmit To
           Callback - Delegate function that holds callback, called on completeion of I/O
           State - State used to track callback, set by caller, not required

        Return Value:

           IAsyncResult - Async result used to retreive result

        --*/
        public IAsyncResult BeginSendTo(byte[] buffer, int offset, int size, SocketFlags socketFlags, EndPoint remoteEP, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginSendTo", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            //
            // parameter validation
            //
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (remoteEP == null)
            {
                throw new ArgumentNullException("remoteEP");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }

            // This will check the permissions for connect.
            EndPoint endPointSnapshot = remoteEP;
            Internals.SocketAddress socketAddress = CheckCacheRemote(ref endPointSnapshot, false);

            // Set up the async result and indicate to flow the context.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Post the send.
            DoBeginSendTo(buffer, offset, size, socketFlags, endPointSnapshot, socketAddress, asyncResult);

            // Finish, possibly posting the callback.  The callback won't be posted before this point is reached.
            asyncResult.FinishPostingAsyncOp(ref Caches.SendClosureCache);

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginSendTo", asyncResult);
            return asyncResult;
        }

        private void DoBeginSendTo(byte[] buffer, int offset, int size, SocketFlags socketFlags, EndPoint endPointSnapshot, Internals.SocketAddress socketAddress, OverlappedAsyncResult asyncResult)
        {
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginSendTo() size:" + size.ToString());
            EndPoint oldEndPoint = m_RightEndPoint;

            // Guarantee to call CheckAsyncCallOverlappedResult if we call SetUnamangedStructures with a cache in order to
            // avoid a Socket leak in case of error.
            SocketError errorCode = SocketError.SocketError;
            try
            {
                if (m_RightEndPoint == null)
                {
                    m_RightEndPoint = endPointSnapshot;
                }

                errorCode = SocketPal.SendToAsync(_handle, buffer, offset, size, socketFlags, socketAddress, asyncResult);

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginSendTo() Interop.Winsock.WSASend returns:" + errorCode.ToString() + " size:" + size + " returning AsyncResult:" + Logging.HashString(asyncResult));
            }
            catch (ObjectDisposedException)
            {
                m_RightEndPoint = oldEndPoint;
                throw;
            }
            finally
            {
                errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);
            }

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                m_RightEndPoint = oldEndPoint;
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginSendTo", socketException);
                throw socketException;
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginSendTo() size:" + size.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
        }

        /*++

        Routine Description:

           EndSendTo -  Called by user code after I/O is done or the user wants to wait.
                        until Async completion, needed to retrieve error result from call

        Arguments:

           AsyncResult - the AsyncResult Returned fron BeginSend call

        Return Value:

           int - Number of bytes transferred

        --*/
        public int EndSendTo(IAsyncResult asyncResult)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndSendTo", asyncResult);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }
            OverlappedAsyncResult castedAsyncResult = asyncResult as OverlappedAsyncResult;
            if (castedAsyncResult == null || castedAsyncResult.AsyncObject != this)
            {
                throw new ArgumentException(SR.net_io_invalidasyncresult, "asyncResult");
            }
            if (castedAsyncResult.EndCalled)
            {
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidendcall, "EndSendTo"));
            }

            int bytesTransferred = (int)castedAsyncResult.InternalWaitForCompletion();
            castedAsyncResult.EndCalled = true;

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesSent, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsSent);
                    }
                }
            }
#endif //!FEATURE_PAL

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndSendTo() bytesTransferred:" + bytesTransferred.ToString());

            //
            // if the asynchronous native call failed asynchronously
            // we'll throw a SocketException
            //
            if ((SocketError)castedAsyncResult.ErrorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException(castedAsyncResult.ErrorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "EndSendTo", socketException);
                throw socketException;
            }
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "EndSendTo", bytesTransferred);
            return bytesTransferred;
        }

        /*++

        Routine Description:

           BeginReceive - Async implimentation of Recv call,

           Called when we want to start an async receive.
           We kick off the receive, and if it completes synchronously we'll
           call the callback. Otherwise we'll return an IASyncResult, which
           the caller can use to wait on or retrieve the final status, as needed.

           Uses Winsock 2 overlapped I/O.

        Arguments:

           ReadBuffer - status line that we wish to parse
           Index - Offset into ReadBuffer to begin reading from
           Size - Size of Buffer to recv
           Callback - Delegate function that holds callback, called on completeion of I/O
           State - State used to track callback, set by caller, not required

        Return Value:

           IAsyncResult - Async result used to retreive result

        --*/
        public IAsyncResult BeginReceive(byte[] buffer, int offset, int size, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            SocketError errorCode;
            IAsyncResult result = BeginReceive(buffer, offset, size, socketFlags, out errorCode, callback, state);
            if (errorCode != SocketError.Success && errorCode != SocketError.IOPending)
            {
                throw new SocketException((int)errorCode);
            }
            return result;
        }

        public IAsyncResult BeginReceive(byte[] buffer, int offset, int size, SocketFlags socketFlags, out SocketError errorCode, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginReceive", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            //
            // parameter validation
            //
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }

            // We need to flow the context here.  But we don't need to lock the context - we don't use it until the callback.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Run the receive with this asyncResult.
            errorCode = DoBeginReceive(buffer, offset, size, socketFlags, asyncResult);

            if (errorCode != SocketError.Success && errorCode != SocketError.IOPending)
            {
                asyncResult = null;
            }
            else
            {
                // We're not throwing, so finish the async op posting code so we can return to the user.
                // If the operation already finished, the callback will be called from here.
                asyncResult.FinishPostingAsyncOp(ref Caches.ReceiveClosureCache);
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginReceive", asyncResult);
            return asyncResult;
        }

        internal IAsyncResult UnsafeBeginReceive(byte[] buffer, int offset, int size, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "UnsafeBeginReceive", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            // No need to flow the context.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);
            DoBeginReceive(buffer, offset, size, socketFlags, asyncResult);

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "UnsafeBeginReceive", asyncResult);
            return asyncResult;
        }

        private SocketError DoBeginReceive(byte[] buffer, int offset, int size, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginReceive() size:" + size.ToString());

#if DEBUG
            IntPtr lastHandle = _handle.DangerousGetHandle();
#endif
            // Guarantee to call CheckAsyncCallOverlappedResult if we call SetUnamangedStructures with a cache in order to
            // avoid a Socket leak in case of error.
            SocketError errorCode = SocketError.SocketError;
            try
            {
                errorCode = SocketPal.ReceiveAsync(_handle, buffer, offset, size, socketFlags, asyncResult);

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginReceive() Interop.Winsock.WSARecv returns:" + errorCode.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
            }
            finally
            {
                errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);
            }

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                GlobalLog.Assert(errorCode != SocketError.Success, "Socket#{0}::DoBeginReceive()|GetLastWin32Error() returned zero.", Logging.HashString(this));

                //
                // update our internal state after this socket error and throw
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginReceive", new SocketException((int)errorCode));
                asyncResult.InvokeCallback(new SocketException((int)errorCode));
            }
#if DEBUG
            else
            {
                _lastReceiveHandle = lastHandle;
                _lastReceiveThread = Environment.CurrentManagedThreadId;
                _lastReceiveTick = Environment.TickCount;
            }
#endif

            return errorCode;
        }

        public IAsyncResult BeginReceive(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            SocketError errorCode;
            IAsyncResult result = BeginReceive(buffers, socketFlags, out errorCode, callback, state);
            if (errorCode != SocketError.Success && errorCode != SocketError.IOPending)
            {
                throw new SocketException((int)errorCode);
            }
            return result;
        }

        public IAsyncResult BeginReceive(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, out SocketError errorCode, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginReceive", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            //
            // parameter validation
            //
            if (buffers == null)
            {
                throw new ArgumentNullException("buffers");
            }

            if (buffers.Count == 0)
            {
                throw new ArgumentException(SR.Format(SR.net_sockets_zerolist, "buffers"), "buffers");
            }

            // We need to flow the context here.  But we don't need to lock the context - we don't use it until the callback.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Run the receive with this asyncResult.
            errorCode = DoBeginReceive(buffers, socketFlags, asyncResult);

            if (errorCode != SocketError.Success && errorCode != SocketError.IOPending)
            {
                asyncResult = null;
            }
            else
            {
                // We're not throwing, so finish the async op posting code so we can return to the user.
                // If the operation already finished, the callback will be called from here.
                asyncResult.FinishPostingAsyncOp(ref Caches.ReceiveClosureCache);
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginReceive", asyncResult);
            return asyncResult;
        }

        private SocketError DoBeginReceive(IList<ArraySegment<byte>> buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
#if DEBUG
            IntPtr lastHandle = _handle.DangerousGetHandle();
#endif
            // Guarantee to call CheckAsyncCallOverlappedResult if we call SetUnamangedStructures with a cache in order to
            // avoid a Socket leak in case of error.
            SocketError errorCode = SocketError.SocketError;
            try
            {
                errorCode = SocketPal.ReceiveAsync(_handle, buffers, socketFlags, asyncResult);

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginReceive() Interop.Winsock.WSARecv returns:" + errorCode.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
            }
            finally
            {
                errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);
            }

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginReceive", new SocketException((int)errorCode));
            }
#if DEBUG
            else
            {
                _lastReceiveHandle = lastHandle;
                _lastReceiveThread = Environment.CurrentManagedThreadId;
                _lastReceiveTick = Environment.TickCount;
            }
#endif

            return errorCode;
        }

#if DEBUG
        private IntPtr _lastReceiveHandle;
        private int _lastReceiveThread;
        private int _lastReceiveTick;
#endif

        /*++

        Routine Description:

           EndReceive -  Called when I/O is done or the user wants to wait. If
                     the I/O isn't done, we'll wait for it to complete, and then we'll return
                     the bytes of I/O done.

        Arguments:

           AsyncResult - the AsyncResult Returned fron BeginSend call

        Return Value:

           int - Number of bytes transferred

        --*/
        public int EndReceive(IAsyncResult asyncResult)
        {
            SocketError errorCode;
            int bytesTransferred = EndReceive(asyncResult, out errorCode);
            if (errorCode != SocketError.Success)
            {
                throw new SocketException((int)errorCode);
            }
            return bytesTransferred;
        }

        public int EndReceive(IAsyncResult asyncResult, out SocketError errorCode)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndReceive", asyncResult);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }
            OverlappedAsyncResult castedAsyncResult = asyncResult as OverlappedAsyncResult;
            if (castedAsyncResult == null || castedAsyncResult.AsyncObject != this)
            {
                throw new ArgumentException(SR.net_io_invalidasyncresult, "asyncResult");
            }
            if (castedAsyncResult.EndCalled)
            {
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidendcall, "EndReceive"));
            }

            int bytesTransferred = (int)castedAsyncResult.InternalWaitForCompletion();
            castedAsyncResult.EndCalled = true;

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesReceived, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsReceived);
                    }
                }
            }
#endif //!FEATURE_PAL

#if TRAVE
            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndReceive() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " bytesTransferred:" + bytesTransferred.ToString());
            }
            catch (ObjectDisposedException) { }
#endif

            //
            // if the asynchronous native call failed asynchronously
            // we'll throw a SocketException
            //
            errorCode = (SocketError)castedAsyncResult.ErrorCode;
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                UpdateStatusAfterSocketError(errorCode);
                if (s_LoggingEnabled)
                {
                    Logging.Exception(Logging.Sockets, this, "EndReceive", new SocketException((int)errorCode));
                    Logging.Exit(Logging.Sockets, this, "EndReceive", 0);
                }
                return 0;
            }
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "EndReceive", bytesTransferred);
            return bytesTransferred;
        }

        public IAsyncResult BeginReceiveMessageFrom(byte[] buffer, int offset, int size, SocketFlags socketFlags, ref EndPoint remoteEP, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginReceiveMessageFrom", "");
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginReceiveMessageFrom() size:" + size.ToString());

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (remoteEP == null)
            {
                throw new ArgumentNullException("remoteEP");
            }
            if (!CanTryAddressFamily(remoteEP.AddressFamily))
            {
                throw new ArgumentException(SR.Format(SR.net_InvalidEndPointAddressFamily,
                    remoteEP.AddressFamily, _addressFamily), "remoteEP");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }
            if (m_RightEndPoint == null)
            {
                throw new InvalidOperationException(SR.net_sockets_mustbind);
            }


            // Set up the result and set it to collect the context.
            ReceiveMessageOverlappedAsyncResult asyncResult = new ReceiveMessageOverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Start the ReceiveFrom.
            EndPoint oldEndPoint = m_RightEndPoint;

            // We don't do a CAS demand here because the contents of remoteEP aren't used by
            // WSARecvMsg; all that matters is that we generate a unique-to-this-call SocketAddress
            // with the right address family
            Internals.SocketAddress socketAddress = SnapshotAndSerialize(ref remoteEP);

            // Guarantee to call CheckAsyncCallOverlappedResult if we call SetUnamangedStructures with a cache in order to
            // avoid a Socket leak in case of error.
            SocketError errorCode = SocketError.SocketError;
            try
            {
                // save a copy of the original EndPoint in the asyncResult
                asyncResult.SocketAddressOriginal = IPEndPointExtensions.Serialize(remoteEP);

                SetReceivingPacketInformation();

                if (m_RightEndPoint == null)
                {
                    m_RightEndPoint = remoteEP;
                }

                errorCode = SocketPal.ReceiveMessageFromAsync(this, _handle, buffer, offset, size, socketFlags, socketAddress, asyncResult);

                if (errorCode != SocketError.Success)
                {
                    // I have guarantees from Brad Williamson that WSARecvMsg() will never return WSAEMSGSIZE directly, since a completion
                    // is queued in this case.  We wouldn't be able to handle this easily because of assumptions OverlappedAsyncResult
                    // makes about whether there would be a completion or not depending on the error code.  If WSAEMSGSIZE would have been
                    // normally returned, it returns WSA_IO_PENDING instead.  That same map is implemented here just in case.
                    if (errorCode == SocketError.MessageSize)
                    {
                        GlobalLog.Assert("Socket#" + Logging.HashString(this) + "::BeginReceiveMessageFrom()|Returned WSAEMSGSIZE!");
                        errorCode = SocketError.IOPending;
                    }
                }

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginReceiveMessageFrom() Interop.Winsock.WSARecvMsg returns:" + errorCode.ToString() + " size:" + size.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
            }
            catch (ObjectDisposedException)
            {
                m_RightEndPoint = oldEndPoint;
                throw;
            }
            finally
            {
                errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);
            }

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                m_RightEndPoint = oldEndPoint;
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginReceiveMessageFrom", socketException);
                throw socketException;
            }

            // Capture the context, maybe call the callback, and return.
            asyncResult.FinishPostingAsyncOp(ref Caches.ReceiveClosureCache);

            if (asyncResult.CompletedSynchronously && !asyncResult.SocketAddressOriginal.Equals(asyncResult.SocketAddress))
            {
                try
                {
                    remoteEP = remoteEP.Create(asyncResult.SocketAddress);
                }
                catch
                {
                }
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginReceiveMessageFrom() size:" + size.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginReceiveMessageFrom", asyncResult);
            return asyncResult;
        }

        public int EndReceiveMessageFrom(IAsyncResult asyncResult, ref SocketFlags socketFlags, ref EndPoint endPoint, out IPPacketInformation ipPacketInformation)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndReceiveMessageFrom", asyncResult);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            if (endPoint == null)
            {
                throw new ArgumentNullException("endPoint");
            }
            if (!CanTryAddressFamily(endPoint.AddressFamily))
            {
                throw new ArgumentException(SR.Format(SR.net_InvalidEndPointAddressFamily,
                    endPoint.AddressFamily, _addressFamily), "endPoint");
            }
            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }
            ReceiveMessageOverlappedAsyncResult castedAsyncResult = asyncResult as ReceiveMessageOverlappedAsyncResult;
            if (castedAsyncResult == null || castedAsyncResult.AsyncObject != this)
            {
                throw new ArgumentException(SR.net_io_invalidasyncresult, "asyncResult");
            }
            if (castedAsyncResult.EndCalled)
            {
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidendcall, "EndReceiveMessageFrom"));
            }

            Internals.SocketAddress socketAddressOriginal = SnapshotAndSerialize(ref endPoint);

            int bytesTransferred = (int)castedAsyncResult.InternalWaitForCompletion();
            castedAsyncResult.EndCalled = true;

            // Update socket address size
            castedAsyncResult.SocketAddress.InternalSize = castedAsyncResult.GetSocketAddressSize();

            if (!socketAddressOriginal.Equals(castedAsyncResult.SocketAddress))
            {
                try
                {
                    endPoint = endPoint.Create(castedAsyncResult.SocketAddress);
                }
                catch
                {
                }
            }

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesReceived, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsReceived);
                    }
                }
            }
#endif //!FEATURE_PAL

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndReceiveMessageFrom() bytesTransferred:" + bytesTransferred.ToString());

            //
            // if the asynchronous native call failed asynchronously
            // we'll throw a SocketException
            //
            if ((SocketError)castedAsyncResult.ErrorCode != SocketError.Success && (SocketError)castedAsyncResult.ErrorCode != SocketError.MessageSize)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException(castedAsyncResult.ErrorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "EndReceiveMessageFrom", socketException);
                throw socketException;
            }

            socketFlags = castedAsyncResult.SocketFlags;
            ipPacketInformation = castedAsyncResult.IPPacketInformation;

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "EndReceiveMessageFrom", bytesTransferred);
            return bytesTransferred;
        }

        /*++

        Routine Description:

           BeginReceiveFrom - Async implimentation of RecvFrom call,

           Called when we want to start an async receive.
           We kick off the receive, and if it completes synchronously we'll
           call the callback. Otherwise we'll return an IASyncResult, which
           the caller can use to wait on or retrieve the final status, as needed.

           Uses Winsock 2 overlapped I/O.

        Arguments:

           ReadBuffer - status line that we wish to parse
           Index - Offset into ReadBuffer to begin reading from
           Request - Size of Buffer to recv
           Flags - Additonal Flags that may be passed to the underlying winsock call
           remoteEP - EndPoint that are to receive from
           Callback - Delegate function that holds callback, called on completeion of I/O
           State - State used to track callback, set by caller, not required

        Return Value:

           IAsyncResult - Async result used to retreive result

        --*/
        public IAsyncResult BeginReceiveFrom(byte[] buffer, int offset, int size, SocketFlags socketFlags, ref EndPoint remoteEP, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginReceiveFrom", "");

            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (remoteEP == null)
            {
                throw new ArgumentNullException("remoteEP");
            }
            if (!CanTryAddressFamily(remoteEP.AddressFamily))
            {
                throw new ArgumentException(SR.Format(SR.net_InvalidEndPointAddressFamily,
                    remoteEP.AddressFamily, _addressFamily), "remoteEP");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (size < 0 || size > buffer.Length - offset)
            {
                throw new ArgumentOutOfRangeException("size");
            }
            if (m_RightEndPoint == null)
            {
                throw new InvalidOperationException(SR.net_sockets_mustbind);
            }

            // We don't do a CAS demand here because the contents of remoteEP aren't used by
            // WSARecvFrom; all that matters is that we generate a unique-to-this-call SocketAddress
            // with the right address family
            Internals.SocketAddress socketAddress = SnapshotAndSerialize(ref remoteEP);

            // Set up the result and set it to collect the context.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Start the ReceiveFrom.
            DoBeginReceiveFrom(buffer, offset, size, socketFlags, remoteEP, socketAddress, asyncResult);

            // Capture the context, maybe call the callback, and return.
            asyncResult.FinishPostingAsyncOp(ref Caches.ReceiveClosureCache);

            if (asyncResult.CompletedSynchronously && !asyncResult.SocketAddressOriginal.Equals(asyncResult.SocketAddress))
            {
                try
                {
                    remoteEP = remoteEP.Create(asyncResult.SocketAddress);
                }
                catch
                {
                }
            }


            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginReceiveFrom", asyncResult);
            return asyncResult;
        }

        private void DoBeginReceiveFrom(byte[] buffer, int offset, int size, SocketFlags socketFlags, EndPoint endPointSnapshot, Internals.SocketAddress socketAddress, OverlappedAsyncResult asyncResult)
        {
            EndPoint oldEndPoint = m_RightEndPoint;
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginReceiveFrom() size:" + size.ToString());

            // Guarantee to call CheckAsyncCallOverlappedResult if we call SetUnamangedStructures with a cache in order to
            // avoid a Socket leak in case of error.
            SocketError errorCode = SocketError.SocketError;
            try
            {
                // save a copy of the original EndPoint in the asyncResult
                asyncResult.SocketAddressOriginal = IPEndPointExtensions.Serialize(endPointSnapshot);

                if (m_RightEndPoint == null)
                {
                    m_RightEndPoint = endPointSnapshot;
                }

                errorCode = SocketPal.ReceiveFromAsync(_handle, buffer, offset, size, socketFlags, socketAddress, asyncResult);

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginReceiveFrom() Interop.Winsock.WSARecvFrom returns:" + errorCode.ToString() + " size:" + size.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
            }
            catch (ObjectDisposedException)
            {
                m_RightEndPoint = oldEndPoint;
                throw;
            }
            finally
            {
                errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);
            }

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                m_RightEndPoint = oldEndPoint;
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginReceiveFrom", socketException);
                throw socketException;
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginReceiveFrom() size:" + size.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
        }

        /*++

        Routine Description:

           EndReceiveFrom -  Called when I/O is done or the user wants to wait. If
                     the I/O isn't done, we'll wait for it to complete, and then we'll return
                     the bytes of I/O done.

        Arguments:

           AsyncResult - the AsyncResult Returned fron BeginReceiveFrom call

        Return Value:

           int - Number of bytes transferred

        --*/
        public int EndReceiveFrom(IAsyncResult asyncResult, ref EndPoint endPoint)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndReceiveFrom", asyncResult);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            if (endPoint == null)
            {
                throw new ArgumentNullException("endPoint");
            }
            if (!CanTryAddressFamily(endPoint.AddressFamily))
            {
                throw new ArgumentException(SR.Format(SR.net_InvalidEndPointAddressFamily,
                    endPoint.AddressFamily, _addressFamily), "endPoint");
            }
            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }
            OverlappedAsyncResult castedAsyncResult = asyncResult as OverlappedAsyncResult;
            if (castedAsyncResult == null || castedAsyncResult.AsyncObject != this)
            {
                throw new ArgumentException(SR.net_io_invalidasyncresult, "asyncResult");
            }
            if (castedAsyncResult.EndCalled)
            {
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidendcall, "EndReceiveFrom"));
            }

            Internals.SocketAddress socketAddressOriginal = SnapshotAndSerialize(ref endPoint);

            int bytesTransferred = (int)castedAsyncResult.InternalWaitForCompletion();
            castedAsyncResult.EndCalled = true;

            // Update socket address size
            castedAsyncResult.SocketAddress.InternalSize = castedAsyncResult.GetSocketAddressSize();

            if (!socketAddressOriginal.Equals(castedAsyncResult.SocketAddress))
            {
                try
                {
                    endPoint = endPoint.Create(castedAsyncResult.SocketAddress);
                }
                catch
                {
                }
            }

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesReceived, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsReceived);
                    }
                }
            }
#endif //!FEATURE_PAL

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndReceiveFrom() bytesTransferred:" + bytesTransferred.ToString());

            //
            // if the asynchronous native call failed asynchronously
            // we'll throw a SocketException
            //
            if ((SocketError)castedAsyncResult.ErrorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException(castedAsyncResult.ErrorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "EndReceiveFrom", socketException);
                throw socketException;
            }
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "EndReceiveFrom", bytesTransferred);
            return bytesTransferred;
        }

        /*++

        Routine Description:

           BeginAccept - Does a async winsock accept, creating a new socket on success

            Works by creating a pending accept request the first time,
            and subsequent calls are queued so that when the first accept completes,
            the next accept can be resubmitted in the callback.
            this routine may go pending at which time,
            but any case the callback Delegate will be called upon completion

        Arguments:

           Callback - Async Callback Delegate that is called upon Async Completion
           State - State used to track callback, set by caller, not required

        Return Value:

           IAsyncResult - Async result used to retreive resultant new socket

        --*/
        public IAsyncResult BeginAccept(AsyncCallback callback, object state)
        {
            if (!_isDisconnected)
            {
                return BeginAccept(0, callback, state);
            }

            if (s_LoggingEnabled)
            {
                Logging.Enter(Logging.Sockets, this, "BeginAccept", "");
            }

            Debug.Assert(CleanedUp);
            throw new ObjectDisposedException(this.GetType().FullName);
        }

        //
        // This is a shortcut to AcceptCallback when called from dispose.
        // The only business is lock and complete all results with an error
        //
        private void CompleteAcceptResults()
        {
            Queue<LazyAsyncResult> acceptQueue = GetAcceptQueue();
            bool acceptNeeded = true;
            while (acceptNeeded)
            {
                LazyAsyncResult asyncResult = null;
                lock (this)
                {
                    // If the queue is empty, cancel the select and indicate not to loop anymore.
                    if (acceptQueue.Count == 0)
                        break;
                    asyncResult = (LazyAsyncResult)acceptQueue.Dequeue();

                    if (acceptQueue.Count == 0)
                        acceptNeeded = false;
                }

                // Notify about the completion outside the lock.
                try
                {
                    asyncResult.InvokeCallback(new SocketException((int)SocketError.OperationAborted));
                }
                catch
                {
                    // Exception from the user callback,
                    // If we need to loop, offload to a different thread and re-throw for debugging
                    if (acceptNeeded)
                    {
                        Task.Factory.StartNew(() => CompleteAcceptResults());
                    }

                    throw;
                }
            }
        }

#if !FEATURE_PAL
        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public IAsyncResult BeginAccept(int receiveSize, AsyncCallback callback, object state)
        {
            return BeginAccept(null, receiveSize, callback, state);
        }

        //  This is the true async version that uses AcceptEx
        public IAsyncResult BeginAccept(Socket acceptSocket, int receiveSize, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginAccept", "");
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            //
            // parameter validation
            //
            if (receiveSize < 0)
            {
                throw new ArgumentOutOfRangeException("size");
            }

            // Set up the async result with flowing.
            AcceptOverlappedAsyncResult asyncResult = new AcceptOverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Start the accept.
            DoBeginAccept(acceptSocket, receiveSize, asyncResult);

            // Finish the flow capture, maybe complete here.
            asyncResult.FinishPostingAsyncOp(ref Caches.AcceptClosureCache);

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginAccept", asyncResult);
            return asyncResult;
        }

        private void DoBeginAccept(Socket acceptSocket, int receiveSize, AcceptOverlappedAsyncResult asyncResult)
        {
            if (m_RightEndPoint == null)
            {
                throw new InvalidOperationException(SR.net_sockets_mustbind);
            }

            if (!_isListening)
            {
                throw new InvalidOperationException(SR.net_sockets_mustlisten);
            }

            SafeCloseSocket acceptHandle;
            asyncResult.AcceptSocket = GetOrCreateAcceptSocket(acceptSocket, false, "acceptSocket", out acceptHandle);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginAccept() AcceptSocket:" + Logging.HashString(acceptSocket));

            int socketAddressSize = m_RightEndPoint.Serialize().Size;
            SocketError errorCode = SocketPal.AcceptAsync(this, _handle, acceptHandle, receiveSize, socketAddressSize, asyncResult);

            errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginAccept() Interop.Winsock.AcceptEx returns:" + errorCode.ToString() + Logging.HashString(asyncResult));

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginAccept", socketException);
                throw socketException;
            }
        }
#endif // !FEATURE_PAL

        /*++

        Routine Description:

           EndAccept -  Called by user code after I/O is done or the user wants to wait.
                        until Async completion, so it provides End handling for aync Accept calls,
                        and retrieves new Socket object

        Arguments:

           AsyncResult - the AsyncResult Returned fron BeginAccept call

        Return Value:

           Socket - a valid socket if successful

        --*/
        public Socket EndAccept(IAsyncResult asyncResult)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndAccept", asyncResult);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

#if !FEATURE_PAL
            if (asyncResult != null && (asyncResult is AcceptOverlappedAsyncResult))
            {
                int bytesTransferred;
                byte[] buffer;
                return EndAccept(out buffer, out bytesTransferred, asyncResult);
            }
#endif // !FEATURE_PAL

            //
            // parameter validation
            //
            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }

            AcceptAsyncResult castedAsyncResult = asyncResult as AcceptAsyncResult;
            if (castedAsyncResult == null || castedAsyncResult.AsyncObject != this)
            {
                throw new ArgumentException(SR.net_io_invalidasyncresult, "asyncResult");
            }
            if (castedAsyncResult.EndCalled)
            {
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidendcall, "EndAccept"));
            }

            object result = castedAsyncResult.InternalWaitForCompletion();
            castedAsyncResult.EndCalled = true;

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndAccept() acceptedSocket:" + Logging.HashString(result));

            //
            // if the asynchronous native call failed asynchronously
            // we'll throw a SocketException
            //
            Exception exception = result as Exception;
            if (exception != null)
            {
                throw exception;
            }

            if ((SocketError)castedAsyncResult.ErrorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException(castedAsyncResult.ErrorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "EndAccept", socketException);
                throw socketException;
            }

            Socket acceptedSocket = (Socket)result;

            if (s_LoggingEnabled)
            {
                Logging.PrintInfo(Logging.Sockets, acceptedSocket,
                    SR.Format(SR.net_log_socket_accepted, acceptedSocket.RemoteEndPoint, acceptedSocket.LocalEndPoint));
                Logging.Exit(Logging.Sockets, this, "EndAccept", result);
            }
            return acceptedSocket;
        }

#if !FEATURE_PAL
        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public Socket EndAccept(out byte[] buffer, IAsyncResult asyncResult)
        {
            int bytesTransferred;
            byte[] innerBuffer;

            Socket socket = EndAccept(out innerBuffer, out bytesTransferred, asyncResult);
            buffer = new byte[bytesTransferred];
            Array.Copy(innerBuffer, buffer, bytesTransferred);
            return socket;
        }

        /// <devdoc>
        ///    <para>[To be supplied.]</para>
        /// </devdoc>
        public Socket EndAccept(out byte[] buffer, out int bytesTransferred, IAsyncResult asyncResult)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndAccept", asyncResult);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            //
            // parameter validation
            //
            if (asyncResult == null)
            {
                throw new ArgumentNullException("asyncResult");
            }
            AcceptOverlappedAsyncResult castedAsyncResult = asyncResult as AcceptOverlappedAsyncResult;
            if (castedAsyncResult == null || castedAsyncResult.AsyncObject != this)
            {
                throw new ArgumentException(SR.net_io_invalidasyncresult, "asyncResult");
            }
            if (castedAsyncResult.EndCalled)
            {
                throw new InvalidOperationException(SR.Format(SR.net_io_invalidendcall, "EndAccept"));
            }

            Socket socket = (Socket)castedAsyncResult.InternalWaitForCompletion();
            bytesTransferred = (int)castedAsyncResult.BytesTransferred;
            buffer = castedAsyncResult.Buffer;

            castedAsyncResult.EndCalled = true;

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesReceived, bytesTransferred);
                }
            }
#endif
            //
            // if the asynchronous native call failed asynchronously
            // we'll throw a SocketException
            //
            if ((SocketError)castedAsyncResult.ErrorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException(castedAsyncResult.ErrorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "EndAccept", socketException);
                throw socketException;
            }

#if TRAVE
            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndAccept() SRC:" + Logging.ObjectToString(LocalEndPoint) + " acceptedSocket:" + Logging.HashString(socket) + " acceptedSocket.SRC:" + Logging.ObjectToString(socket.LocalEndPoint) + " acceptedSocket.DST:" + Logging.ObjectToString(socket.RemoteEndPoint) + " bytesTransferred:" + bytesTransferred.ToString());
            }
            catch (ObjectDisposedException) { }
#endif

            if (s_LoggingEnabled)
            {
                Logging.PrintInfo(Logging.Sockets, socket, SR.Format(SR.net_log_socket_accepted, socket.RemoteEndPoint, socket.LocalEndPoint));
                Logging.Exit(Logging.Sockets, this, "EndAccept", socket);
            }
            return socket;
        }
#endif // !FEATURE_PAL

        /// <devdoc>
        ///    <para>
        ///       Disables sends and receives on a socket.
        ///    </para>
        /// </devdoc>
        public void Shutdown(SocketShutdown how)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Shutdown", how);
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Shutdown() how:" + how.ToString());

            // This can throw ObjectDisposedException.
            SocketError errorCode = SocketPal.Shutdown(_handle, how);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Shutdown() Interop.Winsock.shutdown returns errorCode:" + errorCode);

            //
            // skip good cases: success, socket already closed
            //
            if (errorCode != SocketError.Success && errorCode != SocketError.NotSocket)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "Shutdown", socketException);
                throw socketException;
            }

            SetToDisconnected();
            InternalSetBlocking(_willBlockInternal);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Shutdown", "");
        }

        #region Async methods
        //
        // AcceptAsync
        //        
        public bool AcceptAsync(SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "AcceptAsync", "");

            // Throw if socket disposed
            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            // Throw if multiple buffers specified.
            if (e.m_BufferList != null)
            {
                throw new ArgumentException(SR.net_multibuffernotsupported, "BufferList");
            }

            // Throw if not bound.
            if (m_RightEndPoint == null)
            {
                throw new InvalidOperationException(SR.net_sockets_mustbind);
            }

            // Throw if not listening.
            if (!_isListening)
            {
                throw new InvalidOperationException(SR.net_sockets_mustlisten);
            }

            // Handle AcceptSocket property.
            SafeCloseSocket acceptHandle;
            e.AcceptSocket = GetOrCreateAcceptSocket(e.AcceptSocket, true, "AcceptSocket", out acceptHandle);

            // Prepare for the native call.
            e.StartOperationCommon(this);
            e.StartOperationAccept();

            // Local variables for sync completion.
            int bytesTransferred;
            SocketError socketError = SocketError.Success;

            // Make the native call.
            try
            {
                socketError = e.DoOperationAccept(this, _handle, acceptHandle, out bytesTransferred);
            }
            catch (Exception ex)
            {
                // clear in-use on event arg object 
                e.Complete();
                throw ex;
            }

            // Handle completion when completion port is not posted.
            if (socketError != SocketError.Success && socketError != SocketError.IOPending)
            {
                e.FinishOperationSyncFailure(socketError, bytesTransferred, SocketFlags.None);
                retval = false;
            }
            else
            {
                retval = true;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "AcceptAsync", retval);
            return retval;
        }

        //
        // ConnectAsync
        // 
        public bool ConnectAsync(SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "ConnectAsync", "");

            // Throw if socket disposed
            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            // Throw if multiple buffers specified.
            if (e.m_BufferList != null)
            {
                throw new ArgumentException(SR.net_multibuffernotsupported, "BufferList");
            }

            // Throw if RemoteEndPoint is null.
            if (e.RemoteEndPoint == null)
            {
                throw new ArgumentNullException("remoteEP");
            }
            // Throw if listening.
            if (_isListening)
            {
                throw new InvalidOperationException(SR.net_sockets_mustnotlisten);
            }


            // Check permissions for connect and prepare SocketAddress.
            EndPoint endPointSnapshot = e.RemoteEndPoint;
            DnsEndPoint dnsEP = endPointSnapshot as DnsEndPoint;

            if (dnsEP != null)
            {
                if (s_LoggingEnabled)
                    Logging.PrintInfo(Logging.Sockets, "Socket#" + Logging.HashString(this)
  + "::ConnectAsync " + SR.net_log_socket_connect_dnsendpoint);

                if (dnsEP.AddressFamily != AddressFamily.Unspecified && !CanTryAddressFamily(dnsEP.AddressFamily))
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }

                MultipleConnectAsync multipleConnectAsync = new SingleSocketMultipleConnectAsync(this, true);

                e.StartOperationCommon(this);
                e.StartOperationWrapperConnect(multipleConnectAsync);

                retval = multipleConnectAsync.StartConnectAsync(e, dnsEP);
            }
            else
            {
                // Throw if remote address family doesn't match socket.
                if (!CanTryAddressFamily(e.RemoteEndPoint.AddressFamily))
                {
                    throw new NotSupportedException(SR.net_invalidversion);
                }

                e.m_SocketAddress = CheckCacheRemote(ref endPointSnapshot, false);

                // Do wildcard bind if socket not bound.
                if (m_RightEndPoint == null)
                {
                    if (endPointSnapshot.AddressFamily == AddressFamily.InterNetwork)
                        InternalBind(new IPEndPoint(IPAddress.Any, 0));
                    else
                        InternalBind(new IPEndPoint(IPAddress.IPv6Any, 0));
                }

                // Save the old RightEndPoint and prep new RightEndPoint.           
                EndPoint oldEndPoint = m_RightEndPoint;
                if (m_RightEndPoint == null)
                {
                    m_RightEndPoint = endPointSnapshot;
                }

                // Prepare for the native call.
                e.StartOperationCommon(this);
                e.StartOperationConnect();

                // Make the native call.
                int bytesTransferred;
                SocketError socketError = SocketError.Success;
                try
                {
                    socketError = e.DoOperationConnect(this, _handle, out bytesTransferred);
                }
                catch (Exception ex)
                {
                    m_RightEndPoint = oldEndPoint;
                    // clear in-use on event arg object 
                    e.Complete();
                    throw ex;
                }

                // Handle failure where completion port is not posted.
                if (socketError != SocketError.Success && socketError != SocketError.IOPending)
                {
                    e.FinishOperationSyncFailure(socketError, bytesTransferred, SocketFlags.None);
                    retval = false;
                }
                else
                {
                    retval = true;
                }
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "ConnectAsync", retval);
            return retval;
        }

        public static bool ConnectAsync(SocketType socketType, ProtocolType protocolType, SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, null, "ConnectAsync", "");

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            // Throw if multiple buffers specified.
            if (e.m_BufferList != null)
            {
                throw new ArgumentException(SR.net_multibuffernotsupported, "BufferList");
            }

            // Throw if RemoteEndPoint is null.
            if (e.RemoteEndPoint == null)
            {
                throw new ArgumentNullException("remoteEP");
            }

            EndPoint endPointSnapshot = e.RemoteEndPoint;
            DnsEndPoint dnsEP = endPointSnapshot as DnsEndPoint;

            if (dnsEP != null)
            {
                Socket attemptSocket = null;
                MultipleConnectAsync multipleConnectAsync = null;
                if (dnsEP.AddressFamily == AddressFamily.Unspecified)
                {
                    multipleConnectAsync = new MultipleSocketMultipleConnectAsync(socketType, protocolType);
                }
                else
                {
                    attemptSocket = new Socket(dnsEP.AddressFamily, socketType, protocolType);
                    multipleConnectAsync = new SingleSocketMultipleConnectAsync(attemptSocket, false);
                }

                e.StartOperationCommon(attemptSocket);
                e.StartOperationWrapperConnect(multipleConnectAsync);

                retval = multipleConnectAsync.StartConnectAsync(e, dnsEP);
            }
            else
            {
                Socket attemptSocket = new Socket(endPointSnapshot.AddressFamily, socketType, protocolType);
                retval = attemptSocket.ConnectAsync(e);
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, null, "ConnectAsync", retval);
            return retval;
        }

        public static void CancelConnectAsync(SocketAsyncEventArgs e)
        {
            if (e == null)
            {
                throw new ArgumentNullException("e");
            }
            e.CancelConnectAsync();
        }

        //
        // DisconnectAsync
        // 
        public bool DisconnectAsync(SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "DisconnectAsync", "");

            // Throw if socket disposed
            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            // Prepare for the native call.
            e.StartOperationCommon(this);
            e.StartOperationDisconnect();

            // Make the native call.
            SocketError socketError = SocketError.Success;
            try
            {
                socketError = e.DoOperationDisconnect(this, _handle);
            }
            catch (Exception ex)
            {
                // clear in-use on event arg object 
                e.Complete();
                throw ex;
            }

            // Handle completion when completion port is not posted.
            if (socketError != SocketError.Success && socketError != SocketError.IOPending)
            {
                e.FinishOperationSyncFailure(socketError, 0, SocketFlags.None);
                retval = false;
            }
            else
            {
                retval = true;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "DisconnectAsync", retval);

            return retval;
        }

        //
        // ReceiveAsync
        // 
        public bool ReceiveAsync(SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "ReceiveAsync", "");

            // Throw if socket disposed
            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            // Prepare for the native call.
            e.StartOperationCommon(this);
            e.StartOperationReceive();

            // Local vars for sync completion of native call.
            SocketFlags flags;
            int bytesTransferred;
            SocketError socketError;

            // Wrap native methods with try/catch so event args object can be cleaned up
            try
            {
                socketError = e.DoOperationReceive(_handle, out flags, out bytesTransferred);
            }
            catch (Exception ex)
            {
                // clear in-use on event arg object 
                e.Complete();
                throw ex;
            }

            // Handle completion when completion port is not posted.
            if (socketError != SocketError.Success && socketError != SocketError.IOPending)
            {
                e.FinishOperationSyncFailure(socketError, bytesTransferred, flags);
                retval = false;
            }
            else
            {
                retval = true;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "ReceiveAsync", retval);
            return retval;
        }

        //
        // ReceiveFromAsync
        // 
        public bool ReceiveFromAsync(SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "ReceiveFromAsync", "");

            // Throw if socket disposed
            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            // Throw if remote endpoint property is null.
            if (e.RemoteEndPoint == null)
            {
                throw new ArgumentNullException("RemoteEndPoint");
            }

            if (!CanTryAddressFamily(e.RemoteEndPoint.AddressFamily))
            {
                throw new ArgumentException(SR.Format(SR.net_InvalidEndPointAddressFamily,
                    e.RemoteEndPoint.AddressFamily, _addressFamily), "RemoteEndPoint");
            }

            // We don't do a CAS demand here because the contents of remoteEP aren't used by
            // WSARecvFrom; all that matters is that we generate a unique-to-this-call SocketAddress
            // with the right address family
            EndPoint endPointSnapshot = e.RemoteEndPoint;
            e.m_SocketAddress = SnapshotAndSerialize(ref endPointSnapshot);
            // DualMode may have updated the endPointSnapshot, and it has to have the same AddressFamily as 
            // e.m_SocketAddres for Create to work later.
            e.RemoteEndPoint = endPointSnapshot;

            // Prepare for the native call.
            e.StartOperationCommon(this);
            e.StartOperationReceiveFrom();

            // Make the native call.
            SocketFlags flags;
            int bytesTransferred;
            SocketError socketError;

            try
            {
                socketError = e.DoOperationReceiveFrom(_handle, out flags, out bytesTransferred);
            }
            catch (Exception ex)
            {
                // clear in-use on event arg object 
                e.Complete();
                throw ex;
            }

            // Handle completion when completion port is not posted.
            if (socketError != SocketError.Success && socketError != SocketError.IOPending)
            {
                e.FinishOperationSyncFailure(socketError, bytesTransferred, flags);
                retval = false;
            }
            else
            {
                retval = true;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "ReceiveFromAsync", retval);
            return retval;
        }

        //
        // ReceiveMessageFromAsync
        // 
        public bool ReceiveMessageFromAsync(SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "ReceiveMessageFromAsync", "");

            // Throw if socket disposed
            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            // Throw if remote endpoint property is null.
            if (e.RemoteEndPoint == null)
            {
                throw new ArgumentNullException("RemoteEndPoint");
            }

            if (!CanTryAddressFamily(e.RemoteEndPoint.AddressFamily))
            {
                throw new ArgumentException(SR.Format(SR.net_InvalidEndPointAddressFamily,
                    e.RemoteEndPoint.AddressFamily, _addressFamily), "RemoteEndPoint");
            }

            // We don't do a CAS demand here because the contents of remoteEP aren't used by
            // WSARecvMsg; all that matters is that we generate a unique-to-this-call SocketAddress
            // with the right address family
            EndPoint endPointSnapshot = e.RemoteEndPoint;
            e.m_SocketAddress = SnapshotAndSerialize(ref endPointSnapshot);
            // DualMode may have updated the endPointSnapshot, and it has to have the same AddressFamily as 
            // e.m_SocketAddres for Create to work later.
            e.RemoteEndPoint = endPointSnapshot;

            SetReceivingPacketInformation();

            // Prepare for the native call.
            e.StartOperationCommon(this);
            e.StartOperationReceiveMessageFrom();

            // Make the native call.
            int bytesTransferred;
            SocketError socketError;

            try
            {
                socketError = e.DoOperationReceiveMessageFrom(this, _handle, out bytesTransferred);
            }
            catch (Exception ex)
            {
                // clear in-use on event arg object 
                e.Complete();
                throw ex;
            }

            // Handle completion when completion port is not posted.
            if (socketError != SocketError.Success && socketError != SocketError.IOPending)
            {
                e.FinishOperationSyncFailure(socketError, bytesTransferred, SocketFlags.None);
                retval = false;
            }
            else
            {
                retval = true;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "ReceiveMessageFromAsync", retval);

            return retval;
        }

        //
        // SendAsync
        // 
        public bool SendAsync(SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "SendAsync", "");

            // Throw if socket disposed
            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            // Prepare for the native call.
            e.StartOperationCommon(this);
            e.StartOperationSend();

            // Local vars for sync completion of native call.
            int bytesTransferred;
            SocketError socketError;

            // Wrap native methods with try/catch so event args object can be cleaned up
            try
            {
                socketError = e.DoOperationSend(_handle, out bytesTransferred);
            }
            catch (Exception ex)
            {
                // clear in-use on event arg object 
                e.Complete();
                throw ex;
            }

            // Handle completion when completion port is not posted.
            if (socketError != SocketError.Success && socketError != SocketError.IOPending)
            {
                e.FinishOperationSyncFailure(socketError, bytesTransferred, SocketFlags.None);
                retval = false;
            }
            else
            {
                retval = true;
            }

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "SendAsync", retval);

            return retval;
        }

        //
        // SendPacketsAsync
        // 
        public bool SendPacketsAsync(SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "SendPacketsAsync", "");

            // Throw if socket disposed
            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            if (e.SendPacketsElements == null)
            {
                throw new ArgumentNullException("e.SendPacketsElements");
            }

            // Throw if not connected.
            if (!Connected)
            {
                throw new NotSupportedException(SR.net_notconnected);
            }

            // Prepare for the native call.
            e.StartOperationCommon(this);
            e.StartOperationSendPackets();

            // Make the native call.
            SocketError socketError;

            Debug.Assert(e.SendPacketsDescriptorCount != null);

            if (e.SendPacketsDescriptorCount > 0)
            {
                try
                {
                    socketError = e.DoOperationSendPackets(this, _handle);
                }
                catch (Exception)
                {
                    // clear in-use on event arg object 
                    e.Complete();
                    throw;
                }

                // Handle completion when completion port is not posted.
                if (socketError != SocketError.Success && socketError != SocketError.IOPending)
                {
                    e.FinishOperationSyncFailure(socketError, 0, SocketFlags.None);
                    retval = false;
                }
                else
                {
                    retval = true;
                }
            }
            else
            {
                // No buffers or files to send.
                e.FinishOperationSuccess(SocketError.Success, 0, SocketFlags.None);
                retval = false;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "SendPacketsAsync", retval);

            return retval;
        }

        //
        // SendToAsync
        // 
        public bool SendToAsync(SocketAsyncEventArgs e)
        {
            bool retval;

            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "SendToAsync", "");

            // Throw if socket disposed
            if (CleanedUp)
            {
                throw new ObjectDisposedException(GetType().FullName);
            }

            if (e == null)
            {
                throw new ArgumentNullException("e");
            }

            // Throw if remote endpoint property is null.
            if (e.RemoteEndPoint == null)
            {
                throw new ArgumentNullException("RemoteEndPoint");
            }

            // Check permissions for connect and prepare SocketAddress
            EndPoint endPointSnapshot = e.RemoteEndPoint;
            e.m_SocketAddress = CheckCacheRemote(ref endPointSnapshot, false);

            // Prepare for the native call.
            e.StartOperationCommon(this);
            e.StartOperationSendTo();

            // Make the native call.
            int bytesTransferred;
            SocketError socketError;

            // Wrap native methods with try/catch so event args object can be cleaned up
            try
            {
                socketError = e.DoOperationSendTo(_handle, out bytesTransferred);
            }
            catch (Exception ex)
            {
                // clear in-use on event arg object 
                e.Complete();
                throw ex;
            }

            // Handle completion when completion port is not posted.
            if (socketError != SocketError.Success && socketError != SocketError.IOPending)
            {
                e.FinishOperationSyncFailure(socketError, bytesTransferred, SocketFlags.None);
                retval = false;
            }
            else
            {
                retval = true;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "SendToAsync", retval);

            return retval;
        }
        #endregion

        #endregion

        #region Internal and private properties
        private static object InternalSyncObject
        {
            get
            {
                if (s_InternalSyncObject == null)
                {
                    object o = new object();
                    Interlocked.CompareExchange(ref s_InternalSyncObject, o, null);
                }
                return s_InternalSyncObject;
            }
        }

        private CacheSet Caches
        {
            get
            {
                if (_caches == null)
                {
                    // It's not too bad if extra of these are created and lost.
                    _caches = new CacheSet();
                }
                return _caches;
            }
        }

        private Queue<LazyAsyncResult> GetAcceptQueue()
        {
            if (_acceptQueueOrConnectResult == null)
                Interlocked.CompareExchange(ref _acceptQueueOrConnectResult, new Queue<LazyAsyncResult>(16), null);
            return (Queue<LazyAsyncResult>)_acceptQueueOrConnectResult;
        }

        internal bool CleanedUp
        {
            get
            {
                return (_intCleanedUp == 1);
            }
        }

        internal TransportType Transport
        {
            get
            {
                return
                    _protocolType == Sockets.ProtocolType.Tcp ?
                        TransportType.Tcp :
                        _protocolType == Sockets.ProtocolType.Udp ?
                            TransportType.Udp :
                            TransportType.All;
            }
        }

        #endregion

        #region Internal and private methods

        internal static void GetIPProtocolInformation(AddressFamily addressFamily, Internals.SocketAddress socketAddress, out bool isIPv4, out bool isIPv6)
        {
            bool isIPv4MappedToIPv6 = socketAddress.Family == AddressFamily.InterNetworkV6 && socketAddress.GetIPAddress().IsIPv4MappedToIPv6;
            isIPv4 = addressFamily == AddressFamily.InterNetwork || isIPv4MappedToIPv6; // DualMode
            isIPv6 = addressFamily == AddressFamily.InterNetworkV6;
        }

        private void CheckSetOptionPermissions(SocketOptionLevel optionLevel, SocketOptionName optionName)
        {
            // freely allow only those below
            if (!(optionLevel == SocketOptionLevel.Tcp &&
                  (optionName == SocketOptionName.NoDelay ||
                   optionName == SocketOptionName.BsdUrgent ||
                   optionName == SocketOptionName.Expedited))
                  &&
                  !(optionLevel == SocketOptionLevel.Udp &&
                    (optionName == SocketOptionName.NoChecksum ||
                     optionName == SocketOptionName.ChecksumCoverage))
                  &&
                  !(optionLevel == SocketOptionLevel.Socket &&
                  (optionName == SocketOptionName.KeepAlive ||
                   optionName == SocketOptionName.Linger ||
                   optionName == SocketOptionName.DontLinger ||
                   optionName == SocketOptionName.SendBuffer ||
                   optionName == SocketOptionName.ReceiveBuffer ||
                   optionName == SocketOptionName.SendTimeout ||
                   optionName == SocketOptionName.ExclusiveAddressUse ||
                   optionName == SocketOptionName.ReceiveTimeout))
                  &&
                  //ipv6 protection level
                  !(optionLevel == SocketOptionLevel.IPv6 &&
                    optionName == (SocketOptionName)23))
            {
            }
        }

        private Internals.SocketAddress SnapshotAndSerialize(ref EndPoint remoteEP)
        {
            IPEndPoint ipSnapshot = remoteEP as IPEndPoint;

            if (ipSnapshot != null)
            {
                ipSnapshot = ipSnapshot.Snapshot();
                remoteEP = RemapIPEndPoint(ipSnapshot);
            }

            return CallSerializeCheckDnsEndPoint(remoteEP);
        }

        // Give a nicer exception for DnsEndPoint in cases where it is not supported
        private Internals.SocketAddress CallSerializeCheckDnsEndPoint(EndPoint remoteEP)
        {
            if (remoteEP is DnsEndPoint)
            {
                throw new ArgumentException(SR.Format(SR.net_sockets_invalid_dnsendpoint, "remoteEP"), "remoteEP");
            }

            return IPEndPointExtensions.Serialize(remoteEP);
        }

        // DualMode: Automatically re-map IPv4 addresses to IPv6 addresses
        private IPEndPoint RemapIPEndPoint(IPEndPoint input)
        {
            if (input.AddressFamily == AddressFamily.InterNetwork && IsDualMode)
            {
                return new IPEndPoint(input.Address.MapToIPv6(), input.Port);
            }
            return input;
        }

        //
        // socketAddress must always be the result of remoteEP.Serialize()
        //
        private Internals.SocketAddress CheckCacheRemote(ref EndPoint remoteEP, bool isOverwrite)
        {
            IPEndPoint ipSnapshot = remoteEP as IPEndPoint;

            if (ipSnapshot != null)
            {
                // Snapshot to avoid external tampering and malicious derivations if IPEndPoint
                ipSnapshot = ipSnapshot.Snapshot();
                // DualMode: Do the security check on the user input address, but return an IPEndPoint 
                // mapped to an IPv6 address.
                remoteEP = RemapIPEndPoint(ipSnapshot);
            }

            // This doesn't use SnapshotAndSerialize() because we need the ipSnapshot later.
            Internals.SocketAddress socketAddress = CallSerializeCheckDnsEndPoint(remoteEP);

            // We remember the first peer we have communicated with
            Internals.SocketAddress permittedRemoteAddress = _permittedRemoteAddress;
            if (permittedRemoteAddress != null && permittedRemoteAddress.Equals(socketAddress))
            {
                return permittedRemoteAddress;
            }

            //cache only the first peer we communicated with
            if (_permittedRemoteAddress == null || isOverwrite)
            {
                _permittedRemoteAddress = socketAddress;
            }

            return socketAddress;
        }

        internal static void InitializeSockets()
        {
            if (!s_Initialized)
            {
                lock (InternalSyncObject)
                {
                    if (!s_Initialized)
                    {
                        // TODO: Note for PAL implementation: this call is not required for *NIX and should be avoided during PAL design.

                        // Ensure that WSAStartup has been called once per process.  
                        // The System.Net.NameResolution contract is responsible with the initialization.
                        Dns.GetHostName();

                        // Cache some settings locally.
                        s_PerfCountersEnabled = SocketPerfCounter.Instance.Enabled;
                        s_Initialized = true;
                    }
                }
            }
        }

        internal void InternalConnect(EndPoint remoteEP)
        {
            EndPoint endPointSnapshot = remoteEP;
            Internals.SocketAddress socketAddress = SnapshotAndSerialize(ref endPointSnapshot);
            DoConnect(endPointSnapshot, socketAddress);
        }

        private void DoConnect(EndPoint endPointSnapshot, Internals.SocketAddress socketAddress)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Connect", endPointSnapshot);

            // This can throw ObjectDisposedException.
            SocketError errorCode = SocketPal.Connect(_handle, socketAddress.Buffer, socketAddress.Size);
#if TRAVE
            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::InternalConnect() SRC:" + Logging.ObjectToString(LocalEndPoint) + " DST:" + Logging.ObjectToString(RemoteEndPoint) + " Interop.Winsock.WSAConnect returns errorCode:" + errorCode);
            }
            catch (ObjectDisposedException) { }
#endif

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = SocketExceptionFactory.CreateSocketException(endPointSnapshot);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "Connect", socketException);
                throw socketException;
            }

            if (m_RightEndPoint == null)
            {
                //
                // save a copy of the EndPoint so we can use it for Create()
                //
                m_RightEndPoint = endPointSnapshot;
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoConnect() connection to:" + endPointSnapshot.ToString());

            //
            // update state and performance counter
            //
            SetToConnected();
            if (s_LoggingEnabled)
            {
                Logging.PrintInfo(Logging.Sockets, this, SR.Format(SR.net_log_socket_connected, LocalEndPoint, RemoteEndPoint));
                Logging.Exit(Logging.Sockets, this, "Connect", "");
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposing)
            {
                return;
            }

            try
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Dispose() disposing:true CleanedUp:" + CleanedUp.ToString());
                if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Dispose", null);
            }
            catch (Exception exception)
            {
                if (ExceptionCheck.IsFatal(exception)) throw;
            }

            // make sure we're the first call to Dispose and no SetAsyncEventSelect is in progress
            int last;
            SpinWait sw = new SpinWait();
            while ((last = Interlocked.CompareExchange(ref _intCleanedUp, 1, 0)) == 2)
            {
                sw.SpinOnce();
            }
            if (last == 1)
            {
                try
                {
                    if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Dispose", null);
                }
                catch (Exception exception)
                {
                    if (ExceptionCheck.IsFatal(exception)) throw;
                }
                return;
            }

            SetToDisconnected();

            // Close the handle in one of several ways depending on the timeout.
            // Ignore ObjectDisposedException just in case the handle somehow gets disposed elsewhere.
            try
            {
                int timeout = _closeTimeout;
                if (timeout == 0)
                {
                    // Abortive.
                    GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Dispose() Calling m_Handle.Dispose()");
                    _handle.Dispose();
                }
                else
                {
                    SocketError errorCode;

                    // Go to blocking mode.  We know no WSAEventSelect is pending because of the lock and UnsetAsyncEventSelect() above.
                    if (!_willBlock || !_willBlockInternal)
                    {
                        bool willBlock;
                        errorCode = SocketPal.SetBlocking(_handle, false, out willBlock);
                        GlobalLog.Print("SafeCloseSocket::Dispose(handle:" + _handle.DangerousGetHandle().ToString("x") + ") ioctlsocket(FIONBIO):" + (errorCode == SocketError.SocketError ? SocketPal.GetLastSocketError() : errorCode).ToString());
                    }

                    if (timeout < 0)
                    {
                        // Close with existing user-specified linger option.
                        GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Dispose() Calling m_Handle.CloseAsIs()");
                        _handle.CloseAsIs();
                    }
                    else
                    {
                        // Since our timeout is in ms and linger is in seconds, implement our own sortof linger here.
                        errorCode = SocketPal.Shutdown(_handle, SocketShutdown.Send);
                        GlobalLog.Print("SafeCloseSocket::Dispose(handle:" + _handle.DangerousGetHandle().ToString("x") + ") shutdown():" + (errorCode == SocketError.SocketError ? SocketPal.GetLastSocketError() : errorCode).ToString());

                        // This should give us a timeout in milliseconds.
                        errorCode = SocketPal.SetSockOpt(
                            _handle,
                            SocketOptionLevel.Socket,
                            SocketOptionName.ReceiveTimeout,
                            timeout);
                        GlobalLog.Print("SafeCloseSocket::Dispose(handle:" + _handle.DangerousGetHandle().ToString("x") + ") setsockopt():" + (errorCode == SocketError.SocketError ? SocketPal.GetLastSocketError() : errorCode).ToString());

                        if (errorCode != SocketError.Success)
                        {
                            _handle.Dispose();
                        }
                        else
                        {
                            int unused;
                            errorCode = SocketPal.Receive(_handle, null, 0, 0, SocketFlags.None, out unused);
                            GlobalLog.Print("SafeCloseSocket::Dispose(handle:" + _handle.DangerousGetHandle().ToString("x") + ") recv():" + errorCode.ToString());

                            if (errorCode != (SocketError)0)
                            {
                                // We got a timeout - abort.
                                _handle.Dispose();
                            }
                            else
                            {
                                // We got a FIN or data.  Use ioctlsocket to find out which.
                                int dataAvailable = 0;
                                errorCode = SocketPal.GetAvailable(_handle, out dataAvailable);
                                GlobalLog.Print("SafeCloseSocket::Dispose(handle:" + _handle.DangerousGetHandle().ToString("x") + ") ioctlsocket(FIONREAD):" + (errorCode == SocketError.SocketError ? SocketPal.GetLastSocketError() : errorCode).ToString());

                                if (errorCode != SocketError.Success || dataAvailable != 0)
                                {
                                    // If we have data or don't know, safest thing is to reset.
                                    _handle.Dispose();
                                }
                                else
                                {
                                    // We got a FIN.  It'd be nice to block for the remainder of the timeout for the handshake to finsh.
                                    // Since there's no real way to do that, close the socket with the user's preferences.  This lets
                                    // the user decide how best to handle this case via the linger options.
                                    _handle.CloseAsIs();
                                }
                            }
                        }
                    }
                }
            }
            catch (ObjectDisposedException)
            {
                GlobalLog.Assert("SafeCloseSocket::Dispose(handle:" + _handle.DangerousGetHandle().ToString("x") + ")", "Closing the handle threw ObjectDisposedException.");
            }
        }

        public void Dispose()
        {
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::Dispose() timeout = " + _closeTimeout);
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "Dispose", null);
            Dispose(true);
            GC.SuppressFinalize(this);
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "Dispose", null);
        }

        ~Socket()
        {
            Dispose(false);
        }

        // this version does not throw.
        internal void InternalShutdown(SocketShutdown how)
        {
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::InternalShutdown() how:" + how.ToString());

            if (CleanedUp || _handle.IsInvalid)
            {
                return;
            }

            try
            {
                SocketPal.Shutdown(_handle, how);
            }
            catch (ObjectDisposedException) { }
        }

        // Set the socket option to begin receiving packet information if it has not been
        // set for this socket previously
        internal void SetReceivingPacketInformation()
        {
            if (!_receivingPacketInformation)
            {
                // DualMode: When bound to IPv6Any you must enable both socket options.
                // When bound to an IPv4 mapped IPv6 address you must enable the IPv4 socket option.
                IPEndPoint ipEndPoint = m_RightEndPoint as IPEndPoint;
                IPAddress boundAddress = (ipEndPoint != null ? ipEndPoint.Address : null);
                Debug.Assert(boundAddress != null, "Not Bound");
                if (_addressFamily == AddressFamily.InterNetwork
                    || (boundAddress != null && IsDualMode
                        && (boundAddress.IsIPv4MappedToIPv6 || boundAddress.Equals(IPAddress.IPv6Any))))
                {
                    SetSocketOption(SocketOptionLevel.IP, SocketOptionName.PacketInformation, true);
                }

                if (_addressFamily == AddressFamily.InterNetworkV6
                    && (boundAddress == null || !boundAddress.IsIPv4MappedToIPv6))
                {
                    SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.PacketInformation, true);
                }

                _receivingPacketInformation = true;
            }
        }

        internal unsafe void SetSocketOption(SocketOptionLevel optionLevel, SocketOptionName optionName, int optionValue, bool silent)
        {
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetSocketOption() optionLevel:" + optionLevel + " optionName:" + optionName + " optionValue:" + optionValue + " silent:" + silent);
            if (silent && (CleanedUp || _handle.IsInvalid))
            {
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetSocketOption() skipping the call");
                return;
            }
            SocketError errorCode = SocketError.Success;
            try
            {
                errorCode = SocketPal.SetSockOpt(_handle, optionLevel, optionName, optionValue);

                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetSocketOption() Interop.Winsock.setsockopt returns errorCode:" + errorCode);
            }
            catch
            {
                if (silent && _handle.IsInvalid)
                {
                    return;
                }
                throw;
            }

            // Keep the internal state in sync if the user manually resets this
            if (optionName == SocketOptionName.PacketInformation && optionValue == 0 &&
                errorCode == SocketError.Success)
            {
                _receivingPacketInformation = false;
            }

            if (silent)
            {
                return;
            }

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "SetSocketOption", socketException);
                throw socketException;
            }
        }

        private void setMulticastOption(SocketOptionName optionName, MulticastOption MR)
        {
            SocketError errorCode = SocketPal.SetMulticastOption(_handle, optionName, MR);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::setMulticastOption() Interop.Winsock.setsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "setMulticastOption", socketException);
                throw socketException;
            }
        }

        /// <devdoc>
        ///     <para>
        ///         IPv6 setsockopt for JOIN / LEAVE multicast group
        ///     </para>
        /// </devdoc>
        private void setIPv6MulticastOption(SocketOptionName optionName, IPv6MulticastOption MR)
        {
            SocketError errorCode = SocketPal.SetIPv6MulticastOption(_handle, optionName, MR);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::setIPv6MulticastOption() Interop.Winsock.setsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "setIPv6MulticastOption", socketException);
                throw socketException;
            }
        }

        private void setLingerOption(LingerOption lref)
        {
            SocketError errorCode = SocketPal.SetLingerOption(_handle, lref);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::setLingerOption() Interop.Winsock.setsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "setLingerOption", socketException);
                throw socketException;
            }
        }

        private LingerOption getLingerOpt()
        {
            LingerOption lingerOption;
            SocketError errorCode = SocketPal.GetLingerOption(_handle, out lingerOption);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::getLingerOpt() Interop.Winsock.getsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "getLingerOpt", socketException);
                throw socketException;
            }

            return lingerOption;
        }

        private MulticastOption getMulticastOpt(SocketOptionName optionName)
        {
            MulticastOption multicastOption;
            SocketError errorCode = SocketPal.GetMulticastOption(_handle, optionName, out multicastOption);


            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::getMulticastOpt() Interop.Winsock.getsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "getMulticastOpt", socketException);
                throw socketException;
            }

            return multicastOption;
        }

        /// <devdoc>
        ///     <para>
        ///         IPv6 getsockopt for JOIN / LEAVE multicast group
        ///     </para>
        /// </devdoc>
        private IPv6MulticastOption getIPv6MulticastOpt(SocketOptionName optionName)
        {
            IPv6MulticastOption multicastOption;
            SocketError errorCode = SocketPal.GetIPv6MulticastOption(_handle, optionName, out multicastOption);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::getIPv6MulticastOpt() Interop.Winsock.getsockopt returns errorCode:" + errorCode);

            //
            // if the native call fails we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "getIPv6MulticastOpt", socketException);
                throw socketException;
            }

            return multicastOption;
        }

        //
        // this version will ignore failures but it returns the win32
        // error code, and it will update internal state on success.
        //
        private SocketError InternalSetBlocking(bool desired, out bool current)
        {
            GlobalLog.Enter("Socket#" + Logging.HashString(this) + "::InternalSetBlocking", "desired:" + desired.ToString() + " willBlock:" + _willBlock.ToString() + " willBlockInternal:" + _willBlockInternal.ToString());

            if (CleanedUp)
            {
                GlobalLog.Leave("Socket#" + Logging.HashString(this) + "::InternalSetBlocking", "ObjectDisposed");
                current = _willBlock;
                return SocketError.Success;
            }

            // CONSIDER - can we avoid this call if willBlockInternal is already correct?
            bool willBlock = false;
            SocketError errorCode;
            try
            {
                errorCode = SocketPal.SetBlocking(_handle, desired, out willBlock);
            }
            catch (ObjectDisposedException)
            {
                errorCode = SocketError.NotSocket;
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::InternalSetBlocking() Interop.Winsock.ioctlsocket returns errorCode:" + errorCode);

            //
            // we will update only internal state but only on successfull win32 call
            // so if the native call fails, the state will remain the same.
            //
            if (errorCode == SocketError.Success)
            {
                //
                // success, update internal state
                //
                _willBlockInternal = willBlock;
            }

            GlobalLog.Leave("Socket#" + Logging.HashString(this) + "::InternalSetBlocking", "errorCode:" + errorCode.ToString() + " willBlock:" + _willBlock.ToString() + " willBlockInternal:" + _willBlockInternal.ToString());
            current = _willBlockInternal;
            return errorCode;
        }
        //
        // this version will ignore all failures.
        //
        internal void InternalSetBlocking(bool desired)
        {
            bool current;
            InternalSetBlocking(desired, out current);
        }

        //Implements ConnectEx - this provides completion port IO and support for
        //disconnect and reconnects

        // Since this is private, the unsafe mode is specified with a flag instead of an overload.
        private IAsyncResult BeginConnectEx(EndPoint remoteEP, bool flowContext, AsyncCallback callback, object state)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginConnectEx", "");

            // This will check the permissions for connect.
            EndPoint endPointSnapshot = remoteEP;
            Internals.SocketAddress socketAddress = flowContext ? CheckCacheRemote(ref endPointSnapshot, true) : SnapshotAndSerialize(ref endPointSnapshot);

            //socket must be bound first
            //the calling method BeginConnect will ensure that this method is only
            //called if m_RightEndPoint is not null, of that the endpoint is an ipendpoint
            if (m_RightEndPoint == null)
            {
                GlobalLog.Assert(endPointSnapshot.GetType() == typeof(IPEndPoint), "Socket#{0}::BeginConnectEx()|Socket not bound and endpoint not IPEndPoint.", Logging.HashString(this));
                if (endPointSnapshot.AddressFamily == AddressFamily.InterNetwork)
                    InternalBind(new IPEndPoint(IPAddress.Any, 0));
                else
                    InternalBind(new IPEndPoint(IPAddress.IPv6Any, 0));
            }

            //
            // Allocate the async result and the event we'll pass to the
            // thread pool.
            //
            ConnectOverlappedAsyncResult asyncResult = new ConnectOverlappedAsyncResult(this, endPointSnapshot, state, callback);

            // If context flowing is enabled, set it up here.  No need to lock since the context isn't used until the callback.
            if (flowContext)
            {
                asyncResult.StartPostingAsyncOp(false);
            }

            //we should fix this in Whidbey.
            EndPoint oldEndPoint = m_RightEndPoint;
            if (m_RightEndPoint == null)
            {
                m_RightEndPoint = endPointSnapshot;
            }

            SocketError errorCode;
            try
            {
                errorCode = SocketPal.ConnectAsync(this, _handle, socketAddress.Buffer, socketAddress.Size, asyncResult);
            }
            catch
            {
                //
                // Bug 152350: If ConnectEx throws we need to unpin the socketAddress buffer.
                // m_RightEndPoint will always equal oldEndPoint anyways...
                //
                asyncResult.InternalCleanup();
                m_RightEndPoint = oldEndPoint;
                throw;
            }


            if (errorCode == SocketError.Success)
            {
                SetToConnected();
            }

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginConnectEx() Interop.Winsock.connect returns:" + errorCode.ToString());

            errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                m_RightEndPoint = oldEndPoint;
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginConnectEx", socketException);
                throw socketException;
            }

            // We didn't throw, so indicate that we're returning this result to the user.  This may call the callback.
            // This is a nop if the context isn't being flowed.
            asyncResult.FinishPostingAsyncOp(ref Caches.ConnectClosureCache);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginConnectEx() to:" + endPointSnapshot.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginConnectEx", asyncResult);
            return asyncResult;
        }

        internal void MultipleSend(BufferOffsetSize[] buffers, SocketFlags socketFlags)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "MultipleSend", "");
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            GlobalLog.Assert(buffers != null, "Socket#{0}::MultipleSend()|buffers == null", Logging.HashString(this));
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::MultipleSend() buffers.Length:" + buffers.Length.ToString());

            int bytesTransferred;
            SocketError errorCode = SocketPal.Send(_handle, buffers, socketFlags, out bytesTransferred);

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::MultipleSend() Interop.Winsock.WSASend returns:" + errorCode.ToString() + " size:" + buffers.Length.ToString());

            if (errorCode != SocketError.Success)
            {
                SocketException socketException = new SocketException((int)SocketPal.GetLastSocketError());
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "MultipleSend", socketException);
                throw socketException;
            }

            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "MultipleSend", "");
        }

        private static void DnsCallback(IAsyncResult result)
        {
            if (result.CompletedSynchronously)
                return;

            bool invokeCallback = false;

            MultipleAddressConnectAsyncResult context = (MultipleAddressConnectAsyncResult)result.AsyncState;
            try
            {
                invokeCallback = DoDnsCallback(result, context);
            }
            catch (Exception exception)
            {
                context.InvokeCallback(exception);
            }

            // Invoke the callback outside of the try block so we don't catch user Exceptions
            if (invokeCallback)
            {
                context.InvokeCallback();
            }
        }

        private static bool DoDnsCallback(IAsyncResult result, MultipleAddressConnectAsyncResult context)
        {
            IPAddress[] addresses = DnsAPMExtensions.EndGetHostAddresses(result);
            context.addresses = addresses;
            return DoMultipleAddressConnectCallback(PostOneBeginConnect(context), context);
        }

        private class MultipleAddressConnectAsyncResult : ContextAwareResult
        {
            internal MultipleAddressConnectAsyncResult(IPAddress[] addresses, int port, Socket socket, object myState, AsyncCallback myCallBack) :
                base(socket, myState, myCallBack)
            {
                this.addresses = addresses;
                this.port = port;
                this.socket = socket;
            }

            internal Socket socket;   // Keep this member just to avoid all the casting.
            internal IPAddress[] addresses;
            internal int index;
            internal int port;
            internal Exception lastException;

            internal EndPoint RemoteEndPoint
            {
                get
                {
                    if (addresses != null && index > 0 && index < addresses.Length)
                    {
                        return new IPEndPoint(addresses[index], port);
                    }
                    else
                    {
                        return null;
                    }
                }
            }
        }

        private static object PostOneBeginConnect(MultipleAddressConnectAsyncResult context)
        {
            IPAddress currentAddressSnapshot = context.addresses[context.index];

            if (!context.socket.CanTryAddressFamily(currentAddressSnapshot.AddressFamily))
            {
                return context.lastException != null ? context.lastException : new ArgumentException(SR.net_invalidAddressList, "context");
            }

            try
            {
                EndPoint endPoint = new IPEndPoint(currentAddressSnapshot, context.port);
                // MSRC 11081 - Do the necessary security demand
                context.socket.CheckCacheRemote(ref endPoint, true);

                IAsyncResult connectResult = context.socket.UnsafeBeginConnect(endPoint,
                    new AsyncCallback(MultipleAddressConnectCallback), context);

                if (connectResult.CompletedSynchronously)
                {
                    return connectResult;
                }
            }
            catch (Exception exception)
            {
                if (exception is OutOfMemoryException)
                    throw;

                return exception;
            }

            return null;
        }

        private static void MultipleAddressConnectCallback(IAsyncResult result)
        {
            if (result.CompletedSynchronously)
                return;

            bool invokeCallback = false;

            MultipleAddressConnectAsyncResult context = (MultipleAddressConnectAsyncResult)result.AsyncState;
            try
            {
                invokeCallback = DoMultipleAddressConnectCallback(result, context);
            }
            catch (Exception exception)
            {
                context.InvokeCallback(exception);
            }

            // Invoke the callback outside of the try block so we don't catch user Exceptions
            if (invokeCallback)
            {
                context.InvokeCallback();
            }
        }

        // This is like a regular async callback worker, except the result can be an exception.  This is a useful pattern when
        // processing should continue whether or not an async step failed.
        private static bool DoMultipleAddressConnectCallback(object result, MultipleAddressConnectAsyncResult context)
        {
            while (result != null)
            {
                Exception ex = result as Exception;
                if (ex == null)
                {
                    try
                    {
                        context.socket.EndConnect((IAsyncResult)result);
                    }
                    catch (Exception exception)
                    {
                        ex = exception;
                    }
                }

                if (ex == null)
                {
                    // Don't invoke the callback from here, because we're probably inside
                    // a catch-all block that would eat exceptions from the callback.
                    // Instead tell our caller to invoke the callback outside of its catchall.
                    return true;
                }
                else
                {
                    if (++context.index >= context.addresses.Length)
                        throw ex;

                    context.lastException = ex;
                    result = PostOneBeginConnect(context);
                }
            }

            // Don't invoke the callback at all, because we've posted another async connection attempt
            return false;
        }

        internal IAsyncResult BeginMultipleSend(BufferOffsetSize[] buffers, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            // Set up the async result and start the flow.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);
            asyncResult.StartPostingAsyncOp(false);

            // Start the send.
            DoBeginMultipleSend(buffers, socketFlags, asyncResult);

            // Finish it up (capture, complete).
            asyncResult.FinishPostingAsyncOp(ref Caches.SendClosureCache);
            return asyncResult;
        }

        internal IAsyncResult UnsafeBeginMultipleSend(BufferOffsetSize[] buffers, SocketFlags socketFlags, AsyncCallback callback, object state)
        {
            // Unsafe - don't flow.
            OverlappedAsyncResult asyncResult = new OverlappedAsyncResult(this, state, callback);
            DoBeginMultipleSend(buffers, socketFlags, asyncResult);
            return asyncResult;
        }

        private void DoBeginMultipleSend(BufferOffsetSize[] buffers, SocketFlags socketFlags, OverlappedAsyncResult asyncResult)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "BeginMultipleSend", "");
            if (CleanedUp)
            {
                throw new ObjectDisposedException(this.GetType().FullName);
            }
            //
            // parameter validation
            //
            GlobalLog.Assert(buffers != null, "Socket#{0}::DoBeginMultipleSend()|buffers == null", Logging.HashString(this));
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::DoBeginMultipleSend() buffers.Length:" + buffers.Length.ToString());

            // Guarantee to call CheckAsyncCallOverlappedResult if we call SetUnamangedStructures with a cache in order to
            // avoid a Socket leak in case of error.
            SocketError errorCode = SocketError.SocketError;
            try
            {
                errorCode = SocketPal.SendAsync(_handle, buffers, socketFlags, asyncResult);
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::BeginMultipleSend() Interop.Winsock.WSASend returns:" + errorCode.ToString() + " size:" + buffers.Length.ToString() + " returning AsyncResult:" + Logging.HashString(asyncResult));
            }
            finally
            {
                errorCode = asyncResult.CheckAsyncCallOverlappedResult(errorCode);
            }

            //
            // if the asynchronous native call fails synchronously
            // we'll throw a SocketException
            //
            if (errorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException((int)errorCode);
                UpdateStatusAfterSocketError(socketException);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "BeginMultipleSend", socketException);
                throw socketException;
            }
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "BeginMultipleSend", asyncResult);
        }

        internal int EndMultipleSend(IAsyncResult asyncResult)
        {
            if (s_LoggingEnabled) Logging.Enter(Logging.Sockets, this, "EndMultipleSend", asyncResult);
            //
            // parameter validation
            //
            GlobalLog.Assert(asyncResult != null, "Socket#{0}::EndMultipleSend()|asyncResult == null", Logging.HashString(this));

            OverlappedAsyncResult castedAsyncResult = asyncResult as OverlappedAsyncResult;

            GlobalLog.Assert(castedAsyncResult != null, "Socket#{0}::EndMultipleSend()|castedAsyncResult == null", Logging.HashString(this));
            GlobalLog.Assert(castedAsyncResult.AsyncObject == this, "Socket#{0}::EndMultipleSend()|castedAsyncResult.AsyncObject != this", Logging.HashString(this));
            GlobalLog.Assert(!castedAsyncResult.EndCalled, "Socket#{0}::EndMultipleSend()|castedAsyncResult.EndCalled", Logging.HashString(this));

            int bytesTransferred = (int)castedAsyncResult.InternalWaitForCompletion();
            castedAsyncResult.EndCalled = true;

#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                if (bytesTransferred > 0)
                {
                    SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketBytesSent, bytesTransferred);
                    if (Transport == TransportType.Udp)
                    {
                        SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketDatagramsSent);
                    }
                }
            }
#endif //!FEATURE_PAL

            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::EndMultipleSend() bytesTransferred:" + bytesTransferred.ToString());

            //
            // if the asynchronous native call failed asynchronously
            // we'll throw a SocketException
            //
            if ((SocketError)castedAsyncResult.ErrorCode != SocketError.Success)
            {
                //
                // update our internal state after this socket error and throw
                //
                SocketException socketException = new SocketException(castedAsyncResult.ErrorCode);
                if (s_LoggingEnabled) Logging.Exception(Logging.Sockets, this, "EndMultipleSend", socketException);
                throw socketException;
            }
            if (s_LoggingEnabled) Logging.Exit(Logging.Sockets, this, "EndMultipleSend", bytesTransferred);
            return bytesTransferred;
        }

        //
        // CreateAcceptSocket - pulls unmanaged results and assembles them
        //   into a new Socket object
        //
        internal Socket CreateAcceptSocket(SafeCloseSocket fd, EndPoint remoteEP)
        {
            //
            // Internal state of the socket is inherited from listener
            //
            Socket socket = new Socket(fd);
            return UpdateAcceptSocket(socket, remoteEP);
        }

        internal Socket UpdateAcceptSocket(Socket socket, EndPoint remoteEP)
        {
            //
            // Internal state of the socket is inherited from listener
            //
            socket._addressFamily = _addressFamily;
            socket._socketType = _socketType;
            socket._protocolType = _protocolType;
            socket.m_RightEndPoint = m_RightEndPoint;
            socket.m_RemoteEndPoint = remoteEP;
            //
            // the socket is connected
            //
            socket.SetToConnected();
            //
            // if the socket is returned by an Endb), the socket might have
            // inherited the WSAEventSelect() call from the accepting socket.
            // we need to cancel this otherwise the socket will be in non-blocking
            // mode and we cannot force blocking mode using the ioctlsocket() in
            // Socket.set_Blocking(), since it fails returing 10022 as documented in MSDN.
            // (note that the m_AsyncEvent event will not be created in this case.
            //

            socket._willBlock = _willBlock;
            // We need to make sure the Socket is in the right blocking state
            // even if we don't have to call UnsetAsyncEventSelect
            socket.InternalSetBlocking(_willBlock);

            return socket;
        }

        //
        // SetToConnected - updates the status of the socket to connected
        //
        internal void SetToConnected()
        {
            if (_isConnected)
            {
                //
                // socket was already connected
                //
                return;
            }
            //
            // update the status: this socket was indeed connected at
            // some point in time update the perf counter as well.
            //
            _isConnected = true;
            _isDisconnected = false;
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetToConnected() now connected.");
#if !FEATURE_PAL // perfcounter
            if (s_PerfCountersEnabled)
            {
                SocketPerfCounter.Instance.Increment(SocketPerfCounterName.SocketConnectionsEstablished);
            }
#endif //!FEATURE_PAL
        }

        //
        // SetToDisconnected - updates the status of the socket to disconnected
        //
        internal void SetToDisconnected()
        {
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetToDisconnected()");
            if (!_isConnected)
            {
                //
                // socket was already disconnected
                //
                return;
            }
            //
            // update the status: this socket was indeed disconnected at
            // some point in time, clear any async select bits.
            //
            _isConnected = false;
            _isDisconnected = true;

            if (!CleanedUp)
            {
                //
                // if socket is still alive cancel WSAEventSelect()
                //
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::SetToDisconnected()");
            }
        }

        //
        // UpdateStatusAfterSocketError(socketException) - updates the status of a connected socket
        // on which a failure occured. it'll go to winsock and check if the connection
        // is still open and if it needs to update our internal state.
        //
        internal void UpdateStatusAfterSocketError(SocketException socketException)
        {
            UpdateStatusAfterSocketError(socketException.SocketErrorCode);
        }

        internal void UpdateStatusAfterSocketError(SocketError errorCode)
        {
            //
            // if we already know the socket is disconnected
            // we don't need to do anything else.
            //
            GlobalLog.Print("Socket#" + Logging.HashString(this) + "::UpdateStatusAfterSocketError(socketException)");
            if (s_LoggingEnabled) Logging.PrintError(Logging.Sockets, this, "UpdateStatusAfterSocketError", errorCode.ToString());

            if (_isConnected && (_handle.IsInvalid || (errorCode != SocketError.WouldBlock &&
                    errorCode != SocketError.IOPending && errorCode != SocketError.NoBufferSpaceAvailable &&
                    errorCode != SocketError.TimedOut)))
            {
                //
                //
                // the socket is no longer a valid socket
                //
                GlobalLog.Print("Socket#" + Logging.HashString(this) + "::UpdateStatusAfterSocketError(socketException) Invalidating socket.");
                SetToDisconnected();
            }
        }

        //
        // ValidateBlockingMode - called before synchronous calls to validate
        // the fact that we are in blocking mode (not in non-blocking mode) so the
        // call will actually be synchronous
        //
        private void ValidateBlockingMode()
        {
            if (_willBlock && !_willBlockInternal)
            {
                throw new InvalidOperationException(SR.net_invasync);
            }
        }

        #endregion

#if TRAVE
        [System.Diagnostics.Conditional("TRAVE")]
        internal void DebugMembers() {
            GlobalLog.Print("m_Handle:" + m_Handle.DangerousGetHandle().ToString("x") );
            GlobalLog.Print("m_IsConnected: " + m_IsConnected);
        }
#endif
    }  // end of class Socket

    internal class ConnectAsyncResult : ContextAwareResult
    {
        private EndPoint _endPoint;
        internal ConnectAsyncResult(object myObject, EndPoint endPoint, object myState, AsyncCallback myCallBack) : base(myObject, myState, myCallBack)
        {
            _endPoint = endPoint;
        }
        internal EndPoint RemoteEndPoint
        {
            get { return _endPoint; }
        }
    }

    internal class AcceptAsyncResult : ContextAwareResult
    {
        internal AcceptAsyncResult(object myObject, object myState, AsyncCallback myCallBack) : base(myObject, myState, myCallBack)
        {
        }
    }
}

