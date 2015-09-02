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

        private readonly int _epollFd;

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
                            int epollFd = Interop.libc.epoll_create1(Interop.libc.EPOLL_CLOEXEC);
                            if (epollFd == -1)
                            {
                                // TODO: throw an appropriate exception
                                throw new InternalException();
                            }

                            var engine = new SocketAsyncEngine(epollFd);
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

        private SocketAsyncEngine(int epollFd)
        {
            _epollFd = epollFd;
        }

        private unsafe void EventLoop()
        {
            var events = stackalloc Interop.libc.epoll_event[64];
            for (;;)
            {
                int numEvents = Interop.libc.epoll_wait(_epollFd, events, 64, -1);
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
                    var handle = (GCHandle)events[i].data;
                    var context = (SocketAsyncContext)handle.Target;
                    context.HandleEvents(events[i].events);
                }
            }
        }

        public unsafe bool TryRegister(SocketAsyncContext context, int fileDescriptor, uint events, uint previous, ref GCHandle handle, out Interop.Error error)
        {
            int op = Interop.libc.EPOLL_CTL_MOD;

            // If this context was not listening for events, add it
            if (previous == 0)
            {
                Debug.Assert(!handle.IsAllocated);

                op = Interop.libc.EPOLL_CTL_ADD;
                events |= Interop.libc.EPOLLHUP;
                handle = GCHandle.Alloc(context, GCHandleType.Normal);
            }

            // Register events
            var evt = new Interop.libc.epoll_event { events = events, data = (IntPtr)handle };
            int err = Interop.libc.epoll_ctl(_epollFd, op, fileDescriptor, &evt);
            if (err == 0)
            {
                error = Interop.Error.SUCCESS;
                return true;
            }

            error = Interop.Sys.GetLastError();
            if (previous == 0)
            {
                handle.Free();
            }
            return false;
        }

        public unsafe bool TryUnregister(ref GCHandle handle, int fileDescriptor, uint events, out Interop.Error error)
        {
            int op = Interop.libc.EPOLL_CTL_MOD;

            // If this context will no longer be listening for events, remove it
            if (events == 0)
            {
                op = Interop.libc.EPOLL_CTL_DEL;
            }

            var evt = new Interop.libc.epoll_event { events = events, data = (IntPtr)handle };
            int err = Interop.libc.epoll_ctl(_epollFd, op, fileDescriptor, &evt);
            if (err == 0)
            {
                error = Interop.Error.SUCCESS;
                if (events == 0)
                {
                    handle.Free();
                }
                return true;
            }

            error = Interop.Sys.GetLastError();
            return false;
        }
    }
}
