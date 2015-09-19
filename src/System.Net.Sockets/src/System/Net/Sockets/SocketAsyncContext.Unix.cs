// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;

namespace System.Net.Sockets
{
    // TODO:
    // - Plumb status through async APIs to avoid callbacks on synchronous completion
    //     - NOTE: this will require refactoring in the *Async APIs to accommodate the lack
    //             of completion posting
    // - Add support for unregistering + reregistering for events
    //     - This will require a new state for each queue, unregistred, to track whether or
    //       not the queue is currently registered to receive events
    internal sealed class SocketAsyncContext
    {
        private abstract class AsyncOperation
        {
            private enum State
            {
                Waiting = 0,
                Running = 1,
                Complete = 2,
                Cancelled = 3
            }

            private int _state; // Actually AsyncOperation.State

            public AsyncOperation Next;
            protected object CallbackOrEvent;
            public SocketError ErrorCode;
            public byte[] SocketAddress;
            public int SocketAddressLen;

            public ManualResetEventSlim Event { set { CallbackOrEvent = value; } }

            public AsyncOperation()
            {
                _state = (int)State.Waiting;
                Next = this;
            }

            public void QueueCompletionCallback()
            {
                Debug.Assert(!(CallbackOrEvent is ManualResetEventSlim));
                Debug.Assert(_state != (int)State.Cancelled);

                ThreadPool.QueueUserWorkItem(o => ((AsyncOperation)o).DoCallback(), this);
            }

            public bool TryComplete(int fileDescriptor)
            {
                Debug.Assert(_state == (int)State.Waiting);

                return DoTryComplete(fileDescriptor);
            }

            public bool TryCompleteAsync(int fileDescriptor)
            {
                int state = Interlocked.CompareExchange(ref _state, (int)State.Running, (int)State.Waiting);
                if (state == (int)State.Cancelled)
                {
                    // This operation has been cancelled.
                    return true;
                }
                Debug.Assert(state != (int)State.Complete && state != (int)State.Running);

                if (DoTryComplete(fileDescriptor))
                {
                    var @event = CallbackOrEvent as ManualResetEventSlim;
                    if (@event != null)
                    {
                        @event.Set();
                    }
                    else
                    {
                        QueueCompletionCallback();
                    }
                    Volatile.Write(ref _state, (int)State.Complete);
                    return true;
                }

                Volatile.Write(ref _state, (int)State.Waiting);
                return false;
            }

            public bool Wait(int timeout)
            {
                if (((ManualResetEventSlim)CallbackOrEvent).Wait(timeout))
                {
                    return true;
                }

                for (;;)
                {
                    int state = Interlocked.CompareExchange(ref _state, (int)State.Cancelled, (int)State.Waiting);
                    switch ((State)state)
                    {
                        case State.Running:
                            // A completion attempt is in progress. Keep busy-waiting.
                            break;

                        case State.Complete:
                            // A completion attempt succeeded. Consider this operation as having completed within the timeout.
                            return true;

                        case State.Waiting:
                            // This operation was successfully cancelled.
                            return false;
                    }
                }
            }

            protected abstract bool DoTryComplete(int fileDescriptor);

            protected abstract void DoCallback();
        }

        private abstract class TransferOperation : AsyncOperation
        {
            public byte[] Buffer;
            public int Offset;
            public int Count;
            public int Flags;
            public int BytesTransferred;
            public int ReceivedFlags;
        }

        private abstract class SendReceiveOperation : TransferOperation
        {
            public Action<int, byte[], int, int, SocketError> Callback { set { CallbackOrEvent = value; } }
            public BufferList Buffers;
            public int BufferIndex;

            protected sealed override void DoCallback()
            {
                var callback = (Action<int, byte[], int, int, SocketError>)CallbackOrEvent;
                callback(BytesTransferred, SocketAddress, SocketAddressLen, ReceivedFlags, ErrorCode);
            }
        }

        private sealed class SendOperation : SendReceiveOperation
        {
            protected override bool DoTryComplete(int fileDescriptor)
            {
                return SocketPal.TryCompleteSendTo(fileDescriptor, Buffer, Buffers, ref BufferIndex, ref Offset, ref Count, Flags, SocketAddress, SocketAddressLen, ref BytesTransferred, out ErrorCode);
            }
        }

        private sealed class ReceiveOperation : SendReceiveOperation
        {
            protected override bool DoTryComplete(int fileDescriptor)
            {
                return SocketPal.TryCompleteReceiveFrom(fileDescriptor, Buffer, Buffers, Offset, Count, Flags, SocketAddress, ref SocketAddressLen, out BytesTransferred, out ReceivedFlags, out ErrorCode);
            }
        }

        private sealed class ReceiveMessageFromOperation : TransferOperation
        {
            public Action<int, byte[], int, int, IPPacketInformation, SocketError> Callback { set { CallbackOrEvent = value; } }
            public bool IsIPv4;
            public bool IsIPv6;
            public IPPacketInformation IPPacketInformation;

            protected override bool DoTryComplete(int fileDescriptor)
            {
                return SocketPal.TryCompleteReceiveMessageFrom(fileDescriptor, Buffer, Offset, Count, Flags, SocketAddress, ref SocketAddressLen, IsIPv4, IsIPv6, out BytesTransferred, out ReceivedFlags, out IPPacketInformation, out ErrorCode);
            }

            protected override void DoCallback()
            {
                var callback = (Action<int, byte[], int, int, IPPacketInformation, SocketError>)CallbackOrEvent;
                callback(BytesTransferred, SocketAddress, SocketAddressLen, ReceivedFlags, IPPacketInformation, ErrorCode);
            }
        }

        private abstract class AcceptOrConnectOperation : AsyncOperation
        {
        }

        private sealed class AcceptOperation : AcceptOrConnectOperation
        {
            public Action<int, byte[], int, SocketError> Callback { set { CallbackOrEvent = value; } }
            public int AcceptedFileDescriptor;

            protected override bool DoTryComplete(int fileDescriptor)
            {
                return SocketPal.TryCompleteAccept(fileDescriptor, SocketAddress, ref SocketAddressLen, out AcceptedFileDescriptor, out ErrorCode);
            }

            protected override void DoCallback()
            {
                var callback = (Action<int, byte[], int, SocketError>)CallbackOrEvent;
                callback(AcceptedFileDescriptor, SocketAddress, SocketAddressLen, ErrorCode);
            }
        }

        private sealed class ConnectOperation : AcceptOrConnectOperation
        {
            public Action<SocketError> Callback { set { CallbackOrEvent = value; } }

            protected override bool DoTryComplete(int fileDescriptor)
            {
                return SocketPal.TryCompleteConnect(fileDescriptor, SocketAddressLen, out ErrorCode);

                // The only situation in which we should see EISCONN when completing an
                // async connect is if this earlier connect completed successfully:
                // POSIX does not allow more than one outstanding async connect.
                // if (op.ErrorCode == SocketError.IsConnected)
                // {
                //     op.ErrorCode = SocketError.Success;
                // }
            }

            protected override void DoCallback()
            {
                var callback = (Action<SocketError>)CallbackOrEvent;
                callback(ErrorCode);
            }
        }

        private enum QueueState
        {
            Clear = 0,
            Set = 1,
            Stopped = 2,
        }

        private struct OperationQueue<TOperation>
            where TOperation : AsyncOperation
        {
            private AsyncOperation _tail;

            public QueueState State { get; set; }
            public bool IsStopped { get { return State == QueueState.Stopped; } }
            public bool IsEmpty { get { return _tail == null; } }

            public TOperation Head
            {
                get
                {
                    Debug.Assert(!IsStopped);
                    return (TOperation)_tail.Next;
                }
            }

            public TOperation Tail
            {
                get
                {
                    Debug.Assert(!IsStopped);
                    return (TOperation)_tail;
                }
            }

            public void Enqueue(TOperation operation)
            {
                Debug.Assert(!IsStopped);
                Debug.Assert(operation.Next == operation);

                if (!IsEmpty)
                {
                    operation.Next = _tail.Next;
                    _tail.Next = operation;
                }

                _tail = operation;
            }

            public void Dequeue()
            {
                Debug.Assert(!IsStopped);
                Debug.Assert(!IsEmpty);

                AsyncOperation head = _tail.Next;
                if (head == _tail)
                {
                    _tail = null;
                }
                else
                {
                    _tail.Next = head.Next;
                }
            }

            public OperationQueue<TOperation> Stop()
            {
                OperationQueue<TOperation> result = this;
                _tail = null;
                State = QueueState.Stopped;
                return result;
            }
        }

        private int _fileDescriptor;
        private GCHandle _handle;
        private OperationQueue<TransferOperation> _receiveQueue;
        private OperationQueue<SendOperation> _sendQueue;
        private OperationQueue<AcceptOrConnectOperation> _acceptOrConnectQueue;
        private SocketAsyncEngine _engine;
        private SocketAsyncEvents _registeredEvents;

        // These locks are hierarchical: _closeLock must be acquired before _queueLock in order
        // to prevent deadlock.
        private object _closeLock = new object();
        private object _queueLock = new object();

        public SocketAsyncContext(int fileDescriptor, SocketAsyncEngine engine)
        {
            _fileDescriptor = fileDescriptor;
            _engine = engine;
        }

        private void Register()
        {
            Debug.Assert(Monitor.IsEntered(_queueLock));
            Debug.Assert(!_handle.IsAllocated);
            Debug.Assert(_registeredEvents == SocketAsyncEvents.None);

            _handle = GCHandle.Alloc(this, GCHandleType.Normal);

            const SocketAsyncEvents Events = SocketAsyncEvents.Read | SocketAsyncEvents.Write;

            Interop.Error errorCode;
            if (!_engine.TryRegister(_fileDescriptor, SocketAsyncEvents.None, Events, _handle, out errorCode))
            {
                _handle.Free();

                // TODO: throw an appropiate exception
                throw new Exception(string.Format("SocketAsyncContext.Register: {0}", errorCode));
            }

            _registeredEvents = Events;
        }

        private void UnregisterRead()
        {
            Debug.Assert(Monitor.IsEntered(_queueLock));
            Debug.Assert(_registeredEvents == (SocketAsyncEvents.Read | SocketAsyncEvents.Write));

            SocketAsyncEvents events = _registeredEvents & ~SocketAsyncEvents.Read;

            Interop.Error errorCode;
            if (!_engine.TryRegister(_fileDescriptor, _registeredEvents, events, _handle, out errorCode))
            {
                // TODO: throw an appropiate exception
                throw new Exception(string.Format("UnregisterRead: {0}", errorCode));
            }

            _registeredEvents = events;
        }

        private void Unregister()
        {
            Debug.Assert(Monitor.IsEntered(_queueLock));

            if (_registeredEvents == SocketAsyncEvents.None)
            {
                Debug.Assert(!_handle.IsAllocated);
                return;
            }

            Interop.Error errorCode;
            bool unregistered = _engine.TryRegister(_fileDescriptor, _registeredEvents, SocketAsyncEvents.None, _handle, out errorCode);
            _registeredEvents = (SocketAsyncEvents)(-1);

            if (unregistered || errorCode == Interop.Error.EBADF)
            {
                _registeredEvents = SocketAsyncEvents.None;
                _handle.Free();
            }
        }

        public void Close()
        {
            Debug.Assert(!Monitor.IsEntered(_queueLock));

            OperationQueue<AcceptOrConnectOperation> acceptOrConnectQueue;
            OperationQueue<SendOperation> sendQueue;
            OperationQueue<TransferOperation> receiveQueue;

            lock (_closeLock)
            lock (_queueLock)
            {
                // Drain queues and unregister events

                acceptOrConnectQueue = _acceptOrConnectQueue.Stop();
                sendQueue = _sendQueue.Stop();
                receiveQueue = _receiveQueue.Stop();

                Unregister();

                // TODO: assert that queues are all empty if _registeredEvents was SocketAsyncEvents.None?
            }

            while (!acceptOrConnectQueue.IsEmpty)
            {
                AcceptOrConnectOperation op = acceptOrConnectQueue.Head;
                bool completed = op.TryCompleteAsync(_fileDescriptor);
                Debug.Assert(completed);
                acceptOrConnectQueue.Dequeue();
            }

            while (!sendQueue.IsEmpty)
            {
                SendReceiveOperation op = sendQueue.Head;
                bool completed = op.TryCompleteAsync(_fileDescriptor);
                Debug.Assert(completed);
                sendQueue.Dequeue();
            }

            while (!receiveQueue.IsEmpty)
            {
                TransferOperation op = receiveQueue.Head;
                bool completed = op.TryCompleteAsync(_fileDescriptor);
                Debug.Assert(completed);
                receiveQueue.Dequeue();
            }
        }

        private bool TryBeginOperation<TOperation>(ref OperationQueue<TOperation> queue, TOperation operation, out bool isStopped)
            where TOperation : AsyncOperation
        {
            lock (_queueLock)
            {
                switch (queue.State)
                {
                    case QueueState.Stopped:
                        isStopped = true;
                        return false;

                    case QueueState.Clear:
                        break;

                    case QueueState.Set:
                        isStopped = false;
                        queue.State = QueueState.Clear;
                        return false;
                }

                if (_registeredEvents == SocketAsyncEvents.None)
                {
                    Register();
                }

                queue.Enqueue(operation);
                isStopped = false;
                return true;
            }
        }

        private void EndOperation<TOperation>(ref OperationQueue<TOperation> queue)
            where TOperation : AsyncOperation
        {
            lock (_queueLock)
            {
                Debug.Assert(!queue.IsStopped);

                queue.Dequeue();
            }
        }

        public SocketError Accept(byte[] socketAddress, ref int socketAddressLen, int timeout, out int acceptedFd)
        {
            Debug.Assert(socketAddress != null);
            Debug.Assert(socketAddressLen > 0);
            Debug.Assert(timeout == -1 || timeout > 0);

            SocketError errorCode;
            if (SocketPal.TryCompleteAccept(_fileDescriptor, socketAddress, ref socketAddressLen, out acceptedFd, out errorCode))
            {
                return errorCode;
            }

            using (var @event = new ManualResetEventSlim())
            {
                var operation = new AcceptOperation {
                    Event = @event,
                    SocketAddress = socketAddress,
                    SocketAddressLen = socketAddressLen
                };

                bool isStopped;
                while (!TryBeginOperation(ref _acceptOrConnectQueue, operation, out isStopped))
                {
                    if (isStopped)
                    {
                        // TODO: is this error reasonable for a closed socket? Check with Winsock.
                        acceptedFd = -1;
                        return SocketError.Shutdown;
                    }

                    if (operation.TryComplete(_fileDescriptor))
                    {
                        socketAddressLen = operation.SocketAddressLen;
                        acceptedFd = operation.AcceptedFileDescriptor;
                        return operation.ErrorCode;
                    }
                }

                if (!operation.Wait(timeout))
                {
                    acceptedFd = -1;
                    return SocketError.TimedOut;
                }

                socketAddressLen = operation.SocketAddressLen;
                acceptedFd = operation.AcceptedFileDescriptor;
                return operation.ErrorCode;
            }
        }

        public SocketError AcceptAsync(byte[] socketAddress, int socketAddressLen, Action<int, byte[], int, SocketError> callback)
        {
            Debug.Assert(socketAddress != null);
            Debug.Assert(socketAddressLen > 0);
            Debug.Assert(callback != null);

            int acceptedFd;
            SocketError errorCode;
            if (SocketPal.TryCompleteAccept(_fileDescriptor, socketAddress, ref socketAddressLen, out acceptedFd, out errorCode))
            {
                if (errorCode == SocketError.Success)
                {
                    ThreadPool.QueueUserWorkItem(args =>
                    {
                        var tup = (Tuple<Action<int, byte[], int, SocketError>, int, byte[], int>)args;
                        tup.Item1(tup.Item2, tup.Item3, tup.Item4, SocketError.Success);
                    }, Tuple.Create(callback, acceptedFd, socketAddress, socketAddressLen));
                }
                return errorCode;
            }

            var operation = new AcceptOperation {
                Callback = callback,
                SocketAddress = socketAddress,
                SocketAddressLen = socketAddressLen
            };

            bool isStopped;
            while (!TryBeginOperation(ref _acceptOrConnectQueue, operation, out isStopped))
            {
                if (isStopped)
                {
                    // TODO: is this error reasonable for a closed socket? Check with Winsock.
                    operation.ErrorCode = SocketError.Shutdown;
                    operation.QueueCompletionCallback();
                    return SocketError.Shutdown;
                }

                if (operation.TryComplete(_fileDescriptor))
                {
                    operation.QueueCompletionCallback();
                    break;
                }
            }
            return SocketError.IOPending;
        }

        public SocketError Connect(byte[] socketAddress, int socketAddressLen, int timeout)
        {
            Debug.Assert(socketAddress != null);
            Debug.Assert(socketAddressLen > 0);
            Debug.Assert(timeout == -1 || timeout > 0);

            SocketError errorCode;
            if (SocketPal.TryStartConnect(_fileDescriptor, socketAddress, socketAddressLen, out errorCode))
            {
                return errorCode;
            }

            using (var @event = new ManualResetEventSlim())
            {
                var operation = new ConnectOperation {
                    Event = @event,
                    SocketAddress = socketAddress,
                    SocketAddressLen = socketAddressLen
                };

                bool isStopped;
                while (!TryBeginOperation(ref _acceptOrConnectQueue, operation, out isStopped))
                {
                    if (isStopped)
                    {
                        // TODO: is this error reasonable for a closed socket? Check with Winsock.
                        return SocketError.Shutdown;
                    }

                    if (operation.TryComplete(_fileDescriptor))
                    {
                        return operation.ErrorCode;
                    }
                }

                return operation.Wait(timeout) ? operation.ErrorCode : SocketError.TimedOut;
            }
        }

        public SocketError ConnectAsync(byte[] socketAddress, int socketAddressLen, Action<SocketError> callback)
        {
            Debug.Assert(socketAddress != null);
            Debug.Assert(socketAddressLen > 0);
            Debug.Assert(callback != null);

            SocketError errorCode;
            if (SocketPal.TryStartConnect(_fileDescriptor, socketAddress, socketAddressLen, out errorCode))
            {
                if (errorCode == SocketError.Success)
                {
                    ThreadPool.QueueUserWorkItem(arg => ((Action<SocketError>)arg)(SocketError.Success), callback);
                }
                return errorCode;
            }

            var operation = new ConnectOperation {
                Callback = callback,
                SocketAddress = socketAddress,
                SocketAddressLen = socketAddressLen
            };

            bool isStopped;
            while (!TryBeginOperation(ref _acceptOrConnectQueue, operation, out isStopped))
            {
                if (isStopped)
                {
                    // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                    operation.ErrorCode = SocketError.Shutdown;
                    operation.QueueCompletionCallback();
                    return SocketError.Shutdown;
                }

                if (operation.TryComplete(_fileDescriptor))
                {
                    operation.QueueCompletionCallback();
                    break;
                }
            }
            return SocketError.IOPending;
        }

        public SocketError Receive(byte[] buffer, int offset, int count, ref int flags, int timeout, out int bytesReceived)
        {
            int socketAddressLen = 0;
            return ReceiveFrom(buffer, offset, count, ref flags, null, ref socketAddressLen, timeout, out bytesReceived);
        }

        public SocketError ReceiveAsync(byte[] buffer, int offset, int count, int flags, Action<int, byte[], int, int, SocketError> callback)
        {
            return ReceiveFromAsync(buffer, offset, count, flags, null, 0, callback);
        }

        public SocketError ReceiveFrom(byte[] buffer, int offset, int count, ref int flags, byte[] socketAddress, ref int socketAddressLen, int timeout, out int bytesReceived)
        {
            Debug.Assert(timeout == -1 || timeout > 0);

            int receivedFlags;
            SocketError errorCode;
            if (SocketPal.TryCompleteReceiveFrom(_fileDescriptor, buffer, offset, count, flags, socketAddress, ref socketAddressLen, out bytesReceived, out receivedFlags, out errorCode))
            {
                flags = receivedFlags;
                return errorCode;
            }

            using (var @event = new ManualResetEventSlim())
            {
                var operation = new ReceiveOperation {
                    Event = @event,
                    Buffer = buffer,
                    Offset = offset,
                    Count = count,
                    Flags = flags,
                    SocketAddress = socketAddress,
                    SocketAddressLen = socketAddressLen,
                    BytesTransferred = bytesReceived,
                    ReceivedFlags = receivedFlags
                };

                bool isStopped;
                while (!TryBeginOperation(ref _receiveQueue, operation, out isStopped))
                {
                    if (isStopped)
                    {
                        // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                        flags = operation.ReceivedFlags;
                        bytesReceived = operation.BytesTransferred;
                        return SocketError.Shutdown;
                    }

                    if (operation.TryComplete(_fileDescriptor))
                    {
                        socketAddressLen = operation.SocketAddressLen;
                        flags = operation.ReceivedFlags;
                        bytesReceived = operation.BytesTransferred;
                        return operation.ErrorCode;
                    }
                }

                bool signaled = operation.Wait(timeout);
                socketAddressLen = operation.SocketAddressLen;
                flags = operation.ReceivedFlags;
                bytesReceived = operation.BytesTransferred;
                return signaled ? operation.ErrorCode : SocketError.TimedOut;
            }
        }

        public SocketError ReceiveFromAsync(byte[] buffer, int offset, int count, int flags, byte[] socketAddress, int socketAddressLen, Action<int, byte[], int, int, SocketError> callback)
        {
            int bytesReceived;
            int receivedFlags;
            SocketError errorCode;
            if (SocketPal.TryCompleteReceiveFrom(_fileDescriptor, buffer, offset, count, flags, socketAddress, ref socketAddressLen, out bytesReceived, out receivedFlags, out errorCode))
            {
                if (errorCode == SocketError.Success)
                {
                    ThreadPool.QueueUserWorkItem(args =>
                    {
                        var tup = (Tuple<Action<int, byte[], int, int, SocketError>, int, byte[], int, int>)args;
                        tup.Item1(tup.Item2, tup.Item3, tup.Item4, tup.Item5, SocketError.Success);
                    }, Tuple.Create(callback, bytesReceived, socketAddress, socketAddressLen, receivedFlags));
                }
                return errorCode;
            }

            var operation = new ReceiveOperation {
                Callback = callback,
                Buffer = buffer,
                Offset = offset,
                Count = count,
                Flags = flags,
                SocketAddress = socketAddress,
                SocketAddressLen = socketAddressLen,
                BytesTransferred = bytesReceived,
                ReceivedFlags = receivedFlags
            };

            bool isStopped;
            while (!TryBeginOperation(ref _receiveQueue, operation, out isStopped))
            {
                if (isStopped)
                {
                    // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                    operation.ErrorCode = SocketError.Shutdown;
                    operation.QueueCompletionCallback();
                    return SocketError.Shutdown;
                }

                if (operation.TryComplete(_fileDescriptor))
                {
                    operation.QueueCompletionCallback();
                    break;
                }
            }
            return SocketError.IOPending;
        }

        public SocketError Receive(IList<ArraySegment<byte>> buffers, ref int flags, int timeout, out int bytesReceived)
        {
            return ReceiveFrom(buffers, ref flags, null, 0, timeout, out bytesReceived);
        }

        public SocketError ReceiveAsync(IList<ArraySegment<byte>> buffers, int flags, Action<int, byte[], int, int, SocketError> callback)
        {
            return ReceiveFromAsync(buffers, flags, null, 0, callback);
        }

        public SocketError ReceiveFrom(IList<ArraySegment<byte>> buffers, ref int flags, byte[] socketAddress, int socketAddressLen, int timeout, out int bytesReceived)
        {
            Debug.Assert(timeout == -1 || timeout > 0);

            int receivedFlags;
            SocketError errorCode;
            if (SocketPal.TryCompleteReceiveFrom(_fileDescriptor, buffers, flags, socketAddress, ref socketAddressLen, out bytesReceived, out receivedFlags, out errorCode))
            {
                flags = receivedFlags;
                return errorCode;
            }

            using (var @event = new ManualResetEventSlim())
            {
                var operation = new ReceiveOperation {
                    Event = @event,
                    Buffers = new BufferList(buffers),
                    Flags = flags,
                    SocketAddress = socketAddress,
                    SocketAddressLen = socketAddressLen,
                    BytesTransferred = bytesReceived,
                    ReceivedFlags = receivedFlags
                };

                bool isStopped;
                while (!TryBeginOperation(ref _receiveQueue, operation, out isStopped))
                {
                    if (isStopped)
                    {
                        // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                        flags = operation.ReceivedFlags;
                        bytesReceived = operation.BytesTransferred;
                        return SocketError.Shutdown;
                    }

                    if (operation.TryComplete(_fileDescriptor))
                    {
                        socketAddressLen = operation.SocketAddressLen;
                        flags = operation.ReceivedFlags;
                        bytesReceived = operation.BytesTransferred;
                        return operation.ErrorCode;
                    }
                }

                bool signaled = operation.Wait(timeout);
                socketAddressLen = operation.SocketAddressLen;
                flags = operation.ReceivedFlags;
                bytesReceived = operation.BytesTransferred;
                return signaled ? operation.ErrorCode : SocketError.TimedOut;
            }
        }

        public SocketError ReceiveFromAsync(IList<ArraySegment<byte>> buffers, int flags, byte[] socketAddress, int socketAddressLen, Action<int, byte[], int, int, SocketError> callback)
        {
            int bytesReceived;
            int receivedFlags;
            SocketError errorCode;
            if (SocketPal.TryCompleteReceiveFrom(_fileDescriptor, buffers, flags, socketAddress, ref socketAddressLen, out bytesReceived, out receivedFlags, out errorCode))
            {
                if (errorCode == SocketError.Success)
                {
                    ThreadPool.QueueUserWorkItem(args =>
                    {
                        var tup = (Tuple<Action<int, byte[], int, int, SocketError>, int, byte[], int, int>)args;
                        tup.Item1(tup.Item2, tup.Item3, tup.Item4, tup.Item5, SocketError.Success);
                    }, Tuple.Create(callback, bytesReceived, socketAddress, socketAddressLen, receivedFlags));
                }
                return errorCode;
            }

            var operation = new ReceiveOperation {
                Callback = callback,
                Buffers = new BufferList(buffers),
                Flags = flags,
                SocketAddress = socketAddress,
                SocketAddressLen = socketAddressLen,
                BytesTransferred = bytesReceived,
                ReceivedFlags = receivedFlags
            };

            bool isStopped;
            while (!TryBeginOperation(ref _receiveQueue, operation, out isStopped))
            {
                if (isStopped)
                {
                    // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                    operation.ErrorCode = SocketError.Shutdown;
                    operation.QueueCompletionCallback();
                    return SocketError.Shutdown;
                }

                if (operation.TryComplete(_fileDescriptor))
                {
                    operation.QueueCompletionCallback();
                    break;
                }
            }
            return SocketError.IOPending;
        }

        public SocketError ReceiveMessageFrom(byte[] buffer, int offset, int count, ref int flags, byte[] socketAddress, ref int socketAddressLen, bool isIPv4, bool isIPv6, int timeout, out IPPacketInformation ipPacketInformation, out int bytesReceived)
        {
            Debug.Assert(timeout == -1 || timeout > 0);

            int receivedFlags;
            SocketError errorCode;
            if (SocketPal.TryCompleteReceiveMessageFrom(_fileDescriptor, buffer, offset, count, flags, socketAddress, ref socketAddressLen, isIPv4, isIPv6, out bytesReceived, out receivedFlags, out ipPacketInformation, out errorCode))
            {
                flags = receivedFlags;
                return errorCode;
            }

            using (var @event = new ManualResetEventSlim())
            {
                var operation = new ReceiveMessageFromOperation {
                    Event = @event,
                    Buffer = buffer,
                    Offset = offset,
                    Count = count,
                    Flags = flags,
                    SocketAddress = socketAddress,
                    SocketAddressLen = socketAddressLen,
                    IsIPv4 = isIPv4,
                    IsIPv6 = isIPv6,
                    BytesTransferred = bytesReceived,
                    ReceivedFlags = receivedFlags,
                    IPPacketInformation = ipPacketInformation,
                };

                bool isStopped;
                while (!TryBeginOperation(ref _receiveQueue, operation, out isStopped))
                {
                    if (isStopped)
                    {
                        // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                        socketAddressLen = operation.SocketAddressLen;
                        flags = operation.ReceivedFlags;
                        ipPacketInformation = operation.IPPacketInformation;
                        bytesReceived = operation.BytesTransferred;
                        return SocketError.Shutdown;
                    }

                    if (operation.TryComplete(_fileDescriptor))
                    {
                        socketAddressLen = operation.SocketAddressLen;
                        flags = operation.ReceivedFlags;
                        ipPacketInformation = operation.IPPacketInformation;
                        bytesReceived = operation.BytesTransferred;
                        return operation.ErrorCode;
                    }
                }

                bool signaled = operation.Wait(timeout);
                socketAddressLen = operation.SocketAddressLen;
                flags = operation.ReceivedFlags;
                ipPacketInformation = operation.IPPacketInformation;
                bytesReceived = operation.BytesTransferred;
                return signaled ? operation.ErrorCode : SocketError.TimedOut;
            }
        }

        public SocketError ReceiveMessageFromAsync(byte[] buffer, int offset, int count, int flags, byte[] socketAddress, int socketAddressLen, bool isIPv4, bool isIPv6, Action<int, byte[], int, int, IPPacketInformation, SocketError> callback)
        {
            int bytesReceived;
            int receivedFlags;
            IPPacketInformation ipPacketInformation;
            SocketError errorCode;
            if (SocketPal.TryCompleteReceiveMessageFrom(_fileDescriptor, buffer, offset, count, flags, socketAddress, ref socketAddressLen, isIPv4, isIPv6, out bytesReceived, out receivedFlags, out ipPacketInformation, out errorCode))
            {
                if (errorCode == SocketError.Success)
                {
                    ThreadPool.QueueUserWorkItem(args =>
                    {
                        var tup = (Tuple<Action<int, byte[], int, int, IPPacketInformation, SocketError>, int, byte[], int, int, IPPacketInformation>)args;
                        tup.Item1(tup.Item2, tup.Item3, tup.Item4, tup.Item5, tup.Item6, SocketError.Success);
                    }, Tuple.Create(callback, bytesReceived, socketAddress, socketAddressLen, receivedFlags, ipPacketInformation));
                }
                return errorCode;
            }

            var operation = new ReceiveMessageFromOperation {
                Callback = callback,
                Buffer = buffer,
                Offset = offset,
                Count = count,
                Flags = flags,
                SocketAddress = socketAddress,
                SocketAddressLen = socketAddressLen,
                IsIPv4 = isIPv4,
                IsIPv6 = isIPv6,
                BytesTransferred = bytesReceived,
                ReceivedFlags = receivedFlags,
                IPPacketInformation = ipPacketInformation,
            };

            bool isStopped;
            while (!TryBeginOperation(ref _receiveQueue, operation, out isStopped))
            {
                if (isStopped)
                {
                    // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                    operation.ErrorCode = SocketError.Shutdown;
                    operation.QueueCompletionCallback();
                    return SocketError.Shutdown;
                }

                if (operation.TryComplete(_fileDescriptor))
                {
                    operation.QueueCompletionCallback();
                    break;
                }
            }
            return SocketError.IOPending;
        }

        public SocketError Send(byte[] buffer, int offset, int count, int flags, int timeout, out int bytesSent)
        {
            return SendTo(buffer, offset, count, flags, null, 0, timeout, out bytesSent);
        }

        public SocketError SendAsync(byte[] buffer, int offset, int count, int flags, Action<int, byte[], int, int, SocketError> callback)
        {
            return SendToAsync(buffer, offset, count, flags, null, 0, callback);
        }

        public SocketError SendTo(byte[] buffer, int offset, int count, int flags, byte[] socketAddress, int socketAddressLen, int timeout, out int bytesSent)
        {
            Debug.Assert(timeout == -1 || timeout > 0);

            bytesSent = 0;
            SocketError errorCode;
            if (SocketPal.TryCompleteSendTo(_fileDescriptor, buffer, ref offset, ref count, flags, socketAddress, socketAddressLen, ref bytesSent, out errorCode))
            {
                return errorCode;
            }

            using (var @event = new ManualResetEventSlim())
            {
                var operation = new SendOperation {
                    Event = @event,
                    Buffer = buffer,
                    Offset = offset,
                    Count = count,
                    Flags = flags,
                    SocketAddress = socketAddress,
                    SocketAddressLen = socketAddressLen,
                    BytesTransferred = bytesSent
                };

                bool isStopped;
                while (!TryBeginOperation(ref _sendQueue, operation, out isStopped))
                {
                    if (isStopped)
                    {
                        // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                        bytesSent = operation.BytesTransferred;
                        return SocketError.Shutdown;
                    }

                    if (operation.TryComplete(_fileDescriptor))
                    {
                        bytesSent = operation.BytesTransferred;
                        return operation.ErrorCode;
                    }
                }

                bool signaled = operation.Wait(timeout);
                bytesSent = operation.BytesTransferred;
                return signaled ? operation.ErrorCode : SocketError.TimedOut;
            }
        }

        public SocketError SendToAsync(byte[] buffer, int offset, int count, int flags, byte[] socketAddress, int socketAddressLen, Action<int, byte[], int, int, SocketError> callback)
        {
            int bytesSent = 0;
            SocketError errorCode;
            if (SocketPal.TryCompleteSendTo(_fileDescriptor, buffer, ref offset, ref count, flags, socketAddress, socketAddressLen, ref bytesSent, out errorCode))
            {
                if (errorCode == SocketError.Success)
                {
                    ThreadPool.QueueUserWorkItem(args =>
                    {
                        var tup = (Tuple<Action<int, byte[], int, int, SocketError>, int, byte[], int>)args;
                        tup.Item1(tup.Item2, tup.Item3, tup.Item4, 0, SocketError.Success);
                    }, Tuple.Create(callback, bytesSent, socketAddress, socketAddressLen));
                }
                return errorCode;
            }

            var operation = new SendOperation {
                Callback = callback,
                Buffer = buffer,
                Offset = offset,
                Count = count,
                Flags = flags,
                SocketAddress = socketAddress,
                SocketAddressLen = socketAddressLen,
                BytesTransferred = bytesSent
            };

            bool isStopped;
            while (!TryBeginOperation(ref _sendQueue, operation, out isStopped))
            {
                if (isStopped)
                {
                    // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                    operation.ErrorCode = SocketError.Shutdown;
                    operation.QueueCompletionCallback();
                    return SocketError.Shutdown;
                }

                if (operation.TryComplete(_fileDescriptor))
                {
                    operation.QueueCompletionCallback();
                    break;
                }
            }
            return SocketError.IOPending;
        }

        public SocketError Send(BufferList buffers, int flags, int timeout, out int bytesSent)
        {
            return SendTo(buffers, flags, null, 0, timeout, out bytesSent);
        }

        public SocketError SendAsync(BufferList buffers, int flags, Action<int, byte[], int, int, SocketError> callback)
        {
            return SendToAsync(buffers, flags, null, 0, callback);
        }

        public SocketError SendTo(BufferList buffers, int flags, byte[] socketAddress, int socketAddressLen, int timeout, out int bytesSent)
        {
            Debug.Assert(timeout == -1 || timeout > 0);

            bytesSent = 0;
            int bufferIndex = 0;
            int offset = 0;
            SocketError errorCode;
            if (SocketPal.TryCompleteSendTo(_fileDescriptor, buffers, ref bufferIndex, ref offset, flags, socketAddress, socketAddressLen, ref bytesSent, out errorCode))
            {
                return errorCode;
            }

            using (var @event = new ManualResetEventSlim())
            {
                var operation = new SendOperation {
                    Event = @event,
                    Buffers = buffers,
                    BufferIndex = bufferIndex,
                    Offset = offset,
                    Flags = flags,
                    SocketAddress = socketAddress,
                    SocketAddressLen = socketAddressLen,
                    BytesTransferred = bytesSent
                };

                bool isStopped;
                while (!TryBeginOperation(ref _sendQueue, operation, out isStopped))
                {
                    if (isStopped)
                    {
                        // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                        bytesSent = operation.BytesTransferred;
                        return SocketError.Shutdown;
                    }

                    if (operation.TryComplete(_fileDescriptor))
                    {
                        bytesSent = operation.BytesTransferred;
                        return operation.ErrorCode;
                    }
                }

                bool signaled = operation.Wait(timeout);
                bytesSent = operation.BytesTransferred;
                return signaled ? operation.ErrorCode : SocketError.TimedOut;
            }
        }

        public SocketError SendToAsync(BufferList buffers, int flags, byte[] socketAddress, int socketAddressLen, Action<int, byte[], int, int, SocketError> callback)
        {
            int bufferIndex = 0;
            int offset = 0;
            int bytesSent = 0;
            SocketError errorCode;
            if (SocketPal.TryCompleteSendTo(_fileDescriptor, buffers, ref bufferIndex, ref offset, flags, socketAddress, socketAddressLen, ref bytesSent, out errorCode))
            {
                if (errorCode == SocketError.Success)
                {
                    ThreadPool.QueueUserWorkItem(args =>
                    {
                        var tup = (Tuple<Action<int, byte[], int, int, SocketError>, int, byte[], int>)args;
                        tup.Item1(tup.Item2, tup.Item3, tup.Item4, 0, SocketError.Success);
                    }, Tuple.Create(callback, bytesSent, socketAddress, socketAddressLen));
                }
                return errorCode;
            }

            var operation = new SendOperation {
                Callback = callback,
                Buffers = buffers,
                BufferIndex = bufferIndex,
                Offset = offset,
                Flags = flags,
                SocketAddress = socketAddress,
                SocketAddressLen = socketAddressLen,
                BytesTransferred = bytesSent
            };

            bool isStopped;
            while (!TryBeginOperation(ref _sendQueue, operation, out isStopped))
            {
                if (isStopped)
                {
                    // TODO: is this error code reasonable for a closed socket? Check with Winsock.
                    operation.ErrorCode = SocketError.Shutdown;
                    operation.QueueCompletionCallback();
                    return SocketError.Shutdown;
                }

                if (operation.TryComplete(_fileDescriptor))
                {
                    operation.QueueCompletionCallback();
                    break;
                }
            }
            return SocketError.IOPending;
        }

        public unsafe void HandleEvents(SocketAsyncEvents events)
        {
            Debug.Assert(!Monitor.IsEntered(_queueLock) || Monitor.IsEntered(_closeLock));

            lock (_closeLock)
            {
                if (_registeredEvents == (SocketAsyncEvents)(-1))
                {
                    // This can happen if a previous attempt at unregistration did not succeed.
                    // Retry the unregistration.
                    lock (_queueLock)
                    {
                        Debug.Assert(_acceptOrConnectQueue.IsStopped);
                        Debug.Assert(_sendQueue.IsStopped);
                        Debug.Assert(_receiveQueue.IsStopped);

                        Unregister();
                        return;
                    }
                }

                if ((events & SocketAsyncEvents.Error) != 0)
                {
                    // We should only receive error events in conjuntction with other events.
                    // Processing for those events will pick up the error.
                    Debug.Assert((events & ~SocketAsyncEvents.Error) != 0);
                }

                if ((events & SocketAsyncEvents.ReadClose) != 0)
                {
                    // Drain read queue and unregister read operations
                    Debug.Assert(_acceptOrConnectQueue.IsEmpty);

                    OperationQueue<TransferOperation> receiveQueue;
                    lock (_queueLock)
                    {
                        receiveQueue = _receiveQueue.Stop();
                    }

                    while (!receiveQueue.IsEmpty)
                    {
                        TransferOperation op = receiveQueue.Head;
                        bool completed = op.TryCompleteAsync(_fileDescriptor);
                        Debug.Assert(completed);
                        receiveQueue.Dequeue();
                    }

                    lock (_queueLock)
                    {
                        UnregisterRead();
                    }

                    // Any data left in the socket has been received above; skip further processing.
                    events &= ~SocketAsyncEvents.Read;
                }

                // TODO: optimize locking and completions:
                // - Dequeues (and therefore locking) for multiple contiguous operations can be combined
                // - Contiguous completions can happen in a single thread

                if ((events & SocketAsyncEvents.Read) != 0)
                {
                    AcceptOrConnectOperation acceptTail;
                    TransferOperation receiveTail;
                    lock (_queueLock)
                    {
                        acceptTail = _acceptOrConnectQueue.Tail as AcceptOperation;
                        _acceptOrConnectQueue.State = QueueState.Set;

                        receiveTail = _receiveQueue.Tail;
                        _receiveQueue.State = QueueState.Set;
                    }

                    if (acceptTail != null)
                    {
                        AcceptOrConnectOperation op;
                        do
                        {
                            op = _acceptOrConnectQueue.Head;
                            if (!op.TryCompleteAsync(_fileDescriptor))
                            {
                                break;
                            }
                            EndOperation(ref _acceptOrConnectQueue);
                        } while (op != acceptTail);
                    }

                    if (receiveTail != null)
                    {
                        TransferOperation op;
                        do
                        {
                            op = _receiveQueue.Head;
                            if (!op.TryCompleteAsync(_fileDescriptor))
                            {
                                break;
                            }
                            EndOperation(ref _receiveQueue);
                        } while (op != receiveTail);
                    }
                }

                if ((events & SocketAsyncEvents.Write) != 0)
                {
                    AcceptOrConnectOperation connectTail;
                    SendOperation sendTail;
                    lock (_queueLock)
                    {
                        connectTail = _acceptOrConnectQueue.Tail as ConnectOperation;
                        _acceptOrConnectQueue.State = QueueState.Set;

                        sendTail = _sendQueue.Tail;
                        _sendQueue.State = QueueState.Set;
                    }

                    if (connectTail != null)
                    {
                        AcceptOrConnectOperation op;
                        do
                        {
                            op = _acceptOrConnectQueue.Head;
                            if (!op.TryCompleteAsync(_fileDescriptor))
                            {
                                break;
                            }
                            EndOperation(ref _acceptOrConnectQueue);
                        } while (op != connectTail);
                    }

                    if (sendTail != null)
                    {
                        SendOperation op;
                        do
                        {
                            op = _sendQueue.Head;
                            if (!op.TryCompleteAsync(_fileDescriptor))
                            {
                                break;
                            }
                            EndOperation(ref _sendQueue);
                        } while (op != sendTail);
                    }
                }
            }
        }
    }
}
