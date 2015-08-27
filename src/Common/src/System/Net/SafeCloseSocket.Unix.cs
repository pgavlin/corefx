// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;
using System.Threading;
using Microsoft.Win32.SafeHandles;
using System.Diagnostics;

namespace System.Net.Sockets
{
#if DEBUG
    internal sealed partial class SafeCloseSocket : DebugSafeHandleMinusOneIsInvalid
#else
    internal sealed partial class SafeCloseSocket : SafeHandleMinusOneIsInvalid
#endif
    {
        public SocketAsyncContext AsyncContext
        {
            get
            {
                return _innerSocket.AsyncContext;
            }
        }

		public int FileDescriptor
		{
			get
			{
				return (int)handle;
			}
		}

        public ThreadPoolBoundHandle IOCPBoundHandle
        {
            get
            {
                // TODO: remove this once async sockets are PAL'd out
                throw new PlatformNotSupportedException();
            }
        }

        // TODO: move these to Common
        public static SocketError GetLastSocketError()
        {
            return GetSocketErrorForErrorCode(Interop.Sys.GetLastError());
        }

        public static SocketError GetSocketErrorForErrorCode(Interop.Error errorCode)
        {
            // TODO: audit these using winsock.h
            switch (errorCode)
            {
                case (Interop.Error)0:
                    return SocketError.Success;

                case Interop.Error.EINTR:
                    return SocketError.Interrupted;

                case Interop.Error.EACCES:
                    return SocketError.AccessDenied;

                case Interop.Error.EFAULT:
                    return SocketError.Fault;

                case Interop.Error.EINVAL:
                    return SocketError.InvalidArgument;

                case Interop.Error.EMFILE:
                case Interop.Error.ENFILE:
                    return SocketError.TooManyOpenSockets;

                case Interop.Error.EAGAIN:
                    return SocketError.WouldBlock;

                case Interop.Error.EINPROGRESS:
                    return SocketError.InProgress;

                case Interop.Error.EALREADY:
                    return SocketError.AlreadyInProgress;

                case Interop.Error.ENOTSOCK:
                    return SocketError.NotSocket;

                case Interop.Error.EDESTADDRREQ:
                    return SocketError.DestinationAddressRequired;

                case Interop.Error.EMSGSIZE:
                    return SocketError.MessageSize;

                case Interop.Error.EPROTOTYPE:
                    return SocketError.ProtocolType;

                case Interop.Error.ENOPROTOOPT:
                    return SocketError.ProtocolOption;

                case Interop.Error.EPROTONOSUPPORT:
                    return SocketError.ProtocolNotSupported;

                // SocketError.SocketNotSupported
                // SocketError.OperationNotSupported
                // SocketError.ProtocolFamilyNotSupported

                case Interop.Error.EAFNOSUPPORT:
                    return SocketError.AddressFamilyNotSupported;

                case Interop.Error.EADDRINUSE:
                    return SocketError.AddressAlreadyInUse;

                case Interop.Error.EADDRNOTAVAIL:
                    return SocketError.AddressNotAvailable;

                case Interop.Error.ENETDOWN:
                    return SocketError.NetworkDown;

                case Interop.Error.ENETUNREACH:
                    return SocketError.NetworkUnreachable;

                case Interop.Error.ENETRESET:
                    return SocketError.NetworkReset;

                case Interop.Error.ECONNABORTED:
                    return SocketError.ConnectionAborted;

                case Interop.Error.ECONNRESET:
                    return SocketError.ConnectionReset;

                // SocketError.NoBufferSpaceAvailable

                case Interop.Error.EISCONN:
                    return SocketError.IsConnected;

                case Interop.Error.ENOTCONN:
                    return SocketError.NotConnected;

                // SocketError.Shutdown

                case Interop.Error.ETIMEDOUT:
                    return SocketError.TimedOut;

                case Interop.Error.ECONNREFUSED:
                    return SocketError.ConnectionRefused;

                // SocketError.HostDown

                case Interop.Error.EHOSTUNREACH:
                    return SocketError.HostUnreachable;

                // SocketError.ProcessLimit

                // Extended Windows Sockets error constant definitions
                // SocketError.SystemNotReady
                // SocketError.VersionNotSupported
                // SocketError.NotInitialized
                // SocketError.Disconnecting
                // SocketError.TypeNotFound
                // SocketError.HostNotFound
                // SocketError.TryAgain
                // SocketError.NoRecovery
                // SocketError.NoData

                // OS dependent errors
                // SocketError.IOPending
                // SocketError.OperationAborted

                default:
                    return SocketError.SocketError;
            }
        }

        public static int GetPlatformAddressFamily(AddressFamily addressFamily)
        {
            switch (addressFamily)
            {
                case AddressFamily.Unspecified:
                    return Interop.libc.AF_UNSPEC;

                case AddressFamily.Unix:
                    return Interop.libc.AF_UNIX;

                case AddressFamily.InterNetwork:
                    return Interop.libc.AF_INET;

                case AddressFamily.InterNetworkV6:
                    return Interop.libc.AF_INET6;

                default:
                    return (int)addressFamily;
            }
        }

        public static int GetPlatformProtocolFamily(ProtocolFamily protocolFamily)
        {
            switch (protocolFamily)
            {
                case ProtocolFamily.Unspecified:
                    return Interop.libc.PF_UNSPEC;

                case ProtocolFamily.Unix:
                    return Interop.libc.PF_UNIX;

                case ProtocolFamily.InterNetwork:
                    return Interop.libc.PF_INET;

                case ProtocolFamily.InterNetworkV6:
                    return Interop.libc.PF_INET6;

                default:
                    return (int)protocolFamily;
            }
        }

        public static int GetPlatformSocketType(SocketType socketType)
        {
            switch (socketType)
            {
                case SocketType.Stream:
                    return Interop.libc.SOCK_STREAM;

                case SocketType.Dgram:
                    return Interop.libc.SOCK_DGRAM;

                case SocketType.Raw:
                    return Interop.libc.SOCK_RAW;

                case SocketType.Rdm:
                    return Interop.libc.SOCK_RDM;

                case SocketType.Seqpacket:
                    return Interop.libc.SOCK_SEQPACKET;

                default:
                    return (int)socketType;
            }
        }

        public unsafe static SafeCloseSocket CreateSocket(int fileDescriptor)
        {
            return CreateSocket(InnerSafeCloseSocket.CreateSocket(fileDescriptor));
        }

		public unsafe static SafeCloseSocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
		{
			return CreateSocket(InnerSafeCloseSocket.CreateSocket(addressFamily, socketType, protocolType));
		}

		public unsafe static SafeCloseSocket Accept(SafeCloseSocket socketHandle, byte[] socketAddress, ref int socketAddressSize)
		{
			return CreateSocket(InnerSafeCloseSocket.Accept(socketHandle, socketAddress, ref socketAddressSize));
		}

        public ThreadPoolBoundHandle GetOrAllocateThreadPoolBoundHandle()
        {
            // TODO: remove this once async sockets are PAL'd out
            throw new PlatformNotSupportedException();
        }

        private void InnerReleaseHandle()
        {
			// No-op for Unix.
        }

        internal sealed partial class InnerSafeCloseSocket : SafeHandleMinusOneIsInvalid
        {
            private SocketAsyncContext _asyncContext;

            public SocketAsyncContext AsyncContext
            {
                get
                {
                    if (Volatile.Read(ref _asyncContext) == null)
                    {
                        Interlocked.CompareExchange(ref _asyncContext, new SocketAsyncContext((int)handle, SocketAsyncEngine.Instance), null);
                    }
                    return _asyncContext;
                }
            }

            private unsafe SocketError InnerReleaseHandle()
            {
				int errorCode;

                // If m_Blockable was set in BlockingRelease, it's safe to block here, which means
                // we can honor the linger options set on the socket.  It also means closesocket() might return WSAEWOULDBLOCK, in which
                // case we need to do some recovery.
                if (_blockable)
                {
                    GlobalLog.Print("SafeCloseSocket::ReleaseHandle(handle:" + handle.ToString("x") + ") Following 'blockable' branch.");

					errorCode = Interop.Sys.Close((int)handle);
					if (errorCode == -1)
					{
						errorCode = (int)Interop.Sys.GetLastError();
					}
                    GlobalLog.Print("SafeCloseSocket::ReleaseHandle(handle:" + handle.ToString("x") + ") close()#1:" + errorCode.ToString());

#if DEBUG
                    _closeSocketHandle = handle;
                    _closeSocketResult = GetSocketErrorForErrorCode((Interop.Error)errorCode);
#endif

                    // If it's not EWOULDBLOCK, there's no more recourse - we either succeeded or failed.
					if (errorCode != (int)Interop.Error.EWOULDBLOCK)
                    {
                        if (errorCode == 0)
                        {
                            _asyncContext.Close();
                        }
						return GetSocketErrorForErrorCode((Interop.Error)errorCode);
                    }

                    // The socket must be non-blocking with a linger timeout set.
                    // We have to set the socket to blocking.
                    errorCode = Interop.Sys.Fcntl.SetIsNonBlocking((int)handle, 0);
                    if (errorCode == 0)
                    {
                        // The socket successfully made blocking; retry the close().
                        errorCode = Interop.Sys.Close((int)handle);

                        GlobalLog.Print("SafeCloseSocket::ReleaseHandle(handle:" + handle.ToString("x") + ") close()#2:" + errorCode.ToString());
#if DEBUG
                        _closeSocketHandle = handle;
                        _closeSocketResult = GetSocketErrorForErrorCode((Interop.Error)errorCode);
#endif
                        if (errorCode == 0)
                        {
                            _asyncContext.Close();
                        }
                        return GetSocketErrorForErrorCode((Interop.Error)errorCode);
					}

                    // The socket could not be made blocking; fall through to the regular abortive close.
                }

                // By default or if CloseAsIs() path failed, set linger timeout to zero to get an abortive close (RST).
				var linger = new Interop.libc.linger {
					l_onoff = 1,
					l_linger = 0
				};

				errorCode = Interop.libc.setsockopt((int)handle, Interop.libc.SOL_SOCKET, Interop.libc.SO_LINGER, &linger, (uint)sizeof(Interop.libc.linger));
#if DEBUG
                _closeSocketLinger = GetSocketErrorForErrorCode((Interop.Error)errorCode);
#endif
				if (errorCode == -1)
				{
					errorCode = (int)Interop.Sys.GetLastError();
				}
                GlobalLog.Print("SafeCloseSocket::ReleaseHandle(handle:" + handle.ToString("x") + ") setsockopt():" + errorCode.ToString());

                if (errorCode != 0 && errorCode != (int)Interop.Error.EINVAL && errorCode != (int)Interop.Error.ENOPROTOOPT)
                {
                    // Too dangerous to try closesocket() - it might block!
                    return GetSocketErrorForErrorCode((Interop.Error)errorCode);
                }

                errorCode = Interop.Sys.Close((int)handle);
#if DEBUG
                _closeSocketHandle = handle;
                _closeSocketResult = GetSocketErrorForErrorCode((Interop.Error)errorCode);
#endif
                GlobalLog.Print("SafeCloseSocket::ReleaseHandle(handle:" + handle.ToString("x") + ") close#3():" + (errorCode == -1 ? (int)Interop.Sys.GetLastError() : errorCode).ToString());

                if (errorCode == 0)
                {
                    _asyncContext.Close();
                }
                return GetSocketErrorForErrorCode((Interop.Error)errorCode);
            }

            public static InnerSafeCloseSocket CreateSocket(int fileDescriptor)
            {
                var res = new InnerSafeCloseSocket();
                res.SetHandle((IntPtr)fileDescriptor);
                return res;
            }

			public static InnerSafeCloseSocket CreateSocket(AddressFamily addressFamily, SocketType socketType, ProtocolType protocolType)
			{
                int af = GetPlatformAddressFamily(addressFamily);
                int sock = GetPlatformSocketType(socketType);
                int pt = (int)protocolType;

				int fd = Interop.libc.socket(af, sock, pt);

                var res = new InnerSafeCloseSocket();
                res.SetHandle((IntPtr)fd);
                return res;
			}

			public static unsafe InnerSafeCloseSocket Accept(SafeCloseSocket socketHandle, byte[] socketAddress, ref int socketAddressSize)
			{
				int fd;
				uint addressLen = (uint)socketAddressSize;
				fixed (byte* rawAddress = socketAddress)
				{
					fd = Interop.libc.accept(socketHandle.FileDescriptor, (Interop.libc.sockaddr*)rawAddress, &addressLen);
				}
                socketAddressSize = (int)addressLen;

                var res = new InnerSafeCloseSocket();
                res.SetHandle((IntPtr)fd);
                return res;
			}
        }
    }
}
