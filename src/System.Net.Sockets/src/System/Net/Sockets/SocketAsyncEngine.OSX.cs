// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace System.Net.Sockets
{
    sealed class SocketAsyncEngine
    {
        private static SocketAsyncEngine _engine;
        private static readonly object _initLock = new object();

        private readonly int _kqueueFd;

        public static SocketAsyncEngine Instance
        {
            get
            {
                if (Volatile.Read(ref _engine) == null)
                {
                    lock (_initLock)
                    {
                        if (_engine == null)
                        {
                            int kqueueFd = Interop.libc.kqueue();
                            if (kqueueFd == -1)
                            {
                                // TODO: throw an appropriate exception
                                throw new InternalException();
                            }

                            var engine = new SocketAsyncEngine(kqueueFd);
                            Task.Factory.StartNew(o => {
                                ((SocketAsyncEngine)o).EventLoop();
                            }, engine, TaskCreationOptions.LongRunning);

                            Volatile.Write(ref _engine, engine);
                        }
                    }
                }

                return _engine;
            }
        }

        private SocketAsyncEngine(int kqueueFd)
        {
            _kqueueFd = kqueueFd;
        }

        private unsafe void EventLoop()
        {
            var events = stackalloc Interop.libc.kevent64_s[64];
            for (;;)
            {
                int numEvents = Interop.libc.kevent64(_kqueueFd, null, 0, events, 64, 0, null);
                if (numEvents == -1)
                {
                    // TODO: error handling + EINTR?
                    continue;
                }

                // We should never see 0 events. Given an infinite timeout, epoll_ctl will never return
                // 0 events even if there are no file descriptors registered with the epoll fd. In
                // that case, the wait will block until a file descriptor is added and an event occurs
                // on the added file descriptor.
                Debug.Assert(numEvents != 0);

                for (int i = 0; i < numEvents; i++)
                {
                    var handle = (GCHandle)(IntPtr)events[i].udata;
                    var context = (SocketAsyncContext)handle.Target;
                    context.HandleEvents(events[i].filter, events[i].flags);
                }
            }
        }

        public unsafe bool TryRegister(int fileDescriptor, short filter, GCHandle handle, out Interop.Error error)
        {
            Debug.Assert(handle.IsAllocated);

            // Register events
            var evt = new Interop.libc.kevent64_s {
                ident = unchecked((ulong)fileDescriptor),
                filter = filter,
                flags = Interop.libc.EV_ADD | Interop.libc.EV_CLEAR | Interop.libc.EV_RECEIPT,
                udata = (ulong)(IntPtr)handle
            };
            int err = Interop.libc.kevent64(_kqueueFd, &evt, 1, null, 0, 0, null);
            if (err == 0)
            {
                error = Interop.Error.SUCCESS;
                return true;
            }

            error = Interop.Sys.GetLastError();
            return false;
        }

        public unsafe bool TryUnregister(int fileDescriptor, short filter, GCHandle handle, out Interop.Error error)
        {
            var evt = new Interop.libc.kevent64_s {
                ident = unchecked((ulong)fileDescriptor),
                filter = filter,
                flags = Interop.libc.EV_DELETE | Interop.libc.EV_RECEIPT,
                udata = (ulong)(IntPtr)handle
            };
            int err = Interop.libc.kevent64(_kqueueFd, &evt, 1, null, 0, 0, null);
            if (err == 0)
            {
                error = Interop.Error.SUCCESS;
                return true;
            }

            // EBADF can happen if we attempt to unregister after a call to close(). Ignore it.
            error = Interop.Sys.GetLastError();
            return error == Interop.Error.EBADF;
        }
    }
}
