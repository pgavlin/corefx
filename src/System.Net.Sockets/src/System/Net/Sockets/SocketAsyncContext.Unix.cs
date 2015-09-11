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
            public AsyncOperation Next;
            public SocketError ErrorCode;
            public byte[] SocketAddress;
            public int SocketAddressLen;

            public AsyncOperation()
            {
                Next = this;
            }

            public abstract void Complete();
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

        private sealed class SendReceiveOperation : TransferOperation
        {
            public Action<int, byte[], int, int, SocketError> Callback;
            public BufferList Buffers;
            public int BufferIndex;

            public override void Complete()
            {
                Debug.Assert(Callback != null);

                Callback(BytesTransferred, SocketAddress, SocketAddressLen, ReceivedFlags, ErrorCode);
            }
        }

        private sealed class ReceiveMessageFromOperation : TransferOperation
        {
            public Action<int, byte[], int, int, IPPacketInformation, SocketError> Callback;
            public bool IsIPv4;
            public bool IsIPv6;
            public IPPacketInformation IPPacketInformation;

            public override void Complete()
            {
                Debug.Assert(Callback != null);

                Callback(BytesTransferred, SocketAddress, SocketAddressLen, ReceivedFlags, IPPacketInformation, ErrorCode);
            }
        }

        private abstract class AcceptOrConnectOperation : AsyncOperation
        {
        }

        private sealed class AcceptOperation : AcceptOrConnectOperation
        {
            public Action<int, byte[], int, SocketError> Callback;
            public int AcceptedFileDescriptor;

            public override void Complete()
            {
                Debug.Assert(Callback != null);

                Callback(AcceptedFileDescriptor, SocketAddress, SocketAddressLen, ErrorCode);
            }
        }

        private sealed class ConnectOperation : AcceptOrConnectOperation
        {
            public Action<SocketError> Callback;

            public override void Complete()
            {
                Debug.Assert(Callback != null);

                Callback(ErrorCode);
            }
        }

        private enum State
        {
            Stopped = -1,
            Clear = 0,
            Set = 1,
        }

        private struct OperationQueue<TOperation>
            where TOperation : AsyncOperation
        {
            private AsyncOperation _tail;

            public State State { get; set; }
            public bool IsStopped { get { return State == State.Stopped; } }
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
                State = State.Stopped;
                return result;
            }
        }

        private int _fileDescriptor;
        private GCHandle _handle;
        private OperationQueue<TransferOperation> _receiveQueue;
        private OperationQueue<SendReceiveOperation> _sendQueue;
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
			OperationQueue<SendReceiveOperation> sendQueue;
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

				var acceptOp = op as AcceptOperation;
				bool completed = acceptOp != null ?
					TryCompleteAccept(_fileDescriptor, acceptOp) :
					TryCompleteConnect(_fileDescriptor, (ConnectOperation)op);

				Debug.Assert(completed);
				acceptOrConnectQueue.Dequeue();
				QueueCompletion(op);
			}

			while (!sendQueue.IsEmpty)
			{
				SendReceiveOperation op = sendQueue.Head;
				bool completed = TryCompleteSendTo(_fileDescriptor, op);
				Debug.Assert(completed);
				sendQueue.Dequeue();
				QueueCompletion(op);
			}

			while (!receiveQueue.IsEmpty)
			{
				TransferOperation op = receiveQueue.Head;
				bool completed = TryCompleteReceive(_fileDescriptor, op);
				Debug.Assert(completed);
				receiveQueue.Dequeue();
				QueueCompletion(op);
			}
        }

        private bool TryBeginOperation<TOperation>(ref OperationQueue<TOperation> queue, TOperation operation, out bool isStopped)
            where TOperation : AsyncOperation
        {
            lock (_queueLock)
            {
                switch (queue.State)
                {
                    case State.Stopped:
                        isStopped = true;
                        return false;

                    case State.Clear:
                        break;

                    case State.Set:
                        isStopped = false;
                        queue.State = State.Clear;
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

        public SocketError AcceptAsync(byte[] socketAddress, int socketAddressLen, Action<int, byte[], int, SocketError> callback)
        {
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
                    QueueCompletion(operation);
                    return SocketError.Shutdown;
                }

                if (TryCompleteAccept(_fileDescriptor, operation))
                {
                    QueueCompletion(operation);
                    break;
                }
            }
            return SocketError.IOPending;
        }

        private static bool TryCompleteAccept(int fileDescriptor, AcceptOperation operation)
        {
            return SocketPal.TryCompleteAccept(fileDescriptor, operation.SocketAddress, ref operation.SocketAddressLen, out operation.AcceptedFileDescriptor, out operation.ErrorCode);
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
                    QueueCompletion(operation);
                    return SocketError.Shutdown;
                }

                if (TryCompleteConnect(_fileDescriptor, operation))
                {
                    QueueCompletion(operation);
                    break;
                }
            }
            return SocketError.IOPending;
        }

        private static bool TryCompleteConnect(int fileDescriptor, ConnectOperation operation)
        {
            return SocketPal.TryCompleteConnect(fileDescriptor, operation.SocketAddressLen, out operation.ErrorCode);
        }

        public SocketError ReceiveAsync(byte[] buffer, int offset, int count, int flags, Action<int, byte[], int, int, SocketError> callback)
        {
            return ReceiveFromAsync(buffer, offset, count, flags, null, 0, callback);
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

            var operation = new SendReceiveOperation {
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
                    QueueCompletion(operation);
                    return SocketError.Shutdown;
                }

                if (TryCompleteReceiveFrom(_fileDescriptor, operation))
                {
                    QueueCompletion(operation);
                    break;
                }
            }
            return SocketError.IOPending;
        }

        public SocketError ReceiveAsync(IList<ArraySegment<byte>> buffers, int flags, Action<int, byte[], int, int, SocketError> callback)
        {
            return ReceiveFromAsync(buffers, flags, null, 0, callback);
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

            var operation = new SendReceiveOperation {
                Callback = callback,
                Buffers = new BufferList(buffers),
                Flags = flags,
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
                    QueueCompletion(operation);
                    return SocketError.Shutdown;
                }

                if (TryCompleteReceiveFrom(_fileDescriptor, operation))
                {
                    QueueCompletion(operation);
                    break;
                }
            }
            return SocketError.IOPending;
        }

        private static bool TryCompleteReceiveFrom(int fileDescriptor, SendReceiveOperation operation)
        {
            return SocketPal.TryCompleteReceiveFrom(fileDescriptor, operation.Buffer, operation.Buffers, operation.Offset, operation.Count, operation.Flags, operation.SocketAddress, ref operation.SocketAddressLen, out operation.BytesTransferred, out operation.ReceivedFlags, out operation.ErrorCode);
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
                    QueueCompletion(operation);
                    return SocketError.Shutdown;
                }

                if (TryCompleteReceiveMessageFrom(_fileDescriptor, operation))
                {
                    QueueCompletion(operation);
                    break;
                }
            }
            return SocketError.IOPending;
        }

        private static bool TryCompleteReceiveMessageFrom(int fileDescriptor, ReceiveMessageFromOperation operation)
        {
            return SocketPal.TryCompleteReceiveMessageFrom(fileDescriptor, operation.Buffer, operation.Offset, operation.Count, operation.Flags, operation.SocketAddress, ref operation.SocketAddressLen, operation.IsIPv4, operation.IsIPv6, out operation.BytesTransferred, out operation.ReceivedFlags, out operation.IPPacketInformation, out operation.ErrorCode);
        }

        private static bool TryCompleteReceive(int fileDescriptor, TransferOperation operation)
        {
            var sendReceiveOperation = operation as SendReceiveOperation;
            if (sendReceiveOperation != null)
            {
                return TryCompleteReceiveFrom(fileDescriptor, sendReceiveOperation);
            }

            return TryCompleteReceiveMessageFrom(fileDescriptor, (ReceiveMessageFromOperation)operation);
        }

        public SocketError SendAsync(byte[] buffer, int offset, int count, int flags, Action<int, byte[], int, int, SocketError> callback)
        {
            return SendToAsync(buffer, offset, count, flags, null, 0, callback);
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

            var operation = new SendReceiveOperation {
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
                    QueueCompletion(operation);
                    return SocketError.Shutdown;
                }

                if (TryCompleteSendTo(_fileDescriptor, operation))
                {
                    QueueCompletion(operation);
                    break;
                }
            }
            return SocketError.IOPending;
        }

        public SocketError SendAsync(BufferList buffers, int flags, Action<int, byte[], int, int, SocketError> callback)
        {
            return SendToAsync(buffers, flags, null, 0, callback);
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

            var operation = new SendReceiveOperation {
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
                    QueueCompletion(operation);
                    return SocketError.Shutdown;
                }

                if (TryCompleteSendTo(_fileDescriptor, operation))
                {
                    QueueCompletion(operation);
                    break;
                }
            }
            return SocketError.IOPending;
        }

        private static bool TryCompleteSendTo(int fileDescriptor, SendReceiveOperation operation)
        {
            return SocketPal.TryCompleteSendTo(fileDescriptor, operation.Buffer, operation.Buffers, ref operation.BufferIndex, ref operation.Offset, ref operation.Count, operation.Flags, operation.SocketAddress, operation.SocketAddressLen, ref operation.BytesTransferred, out operation.ErrorCode);
        }

        private static void QueueCompletion(AsyncOperation operation)
        {
            ThreadPool.QueueUserWorkItem(o => ((AsyncOperation)o).Complete(), operation);
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
                        bool completed = TryCompleteReceive(_fileDescriptor, op);
                        Debug.Assert(completed);
                        receiveQueue.Dequeue();
                        QueueCompletion(op);
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
						_acceptOrConnectQueue.State = State.Set;

                        receiveTail = _receiveQueue.Tail;
                        _receiveQueue.State = State.Set;
                    }

                    if (acceptTail != null)
                    {
                        AcceptOperation op;
                        do
                        {
                            op = (AcceptOperation)_acceptOrConnectQueue.Head;
                            if (TryCompleteAccept(_fileDescriptor, op))
                            {
                                EndOperation(ref _acceptOrConnectQueue);
                                QueueCompletion(op);
                            }
                            break;
                        } while (op != acceptTail);
                    }

                    if (receiveTail != null)
                    {
                        TransferOperation op;
                        do
                        {
                            op = _receiveQueue.Head;
                            if (TryCompleteReceive(_fileDescriptor, op))
                            {
                                EndOperation(ref _receiveQueue);
                                QueueCompletion(op);
                            }
                            break;
                        } while (op != receiveTail);
                    }
                }

                if ((events & SocketAsyncEvents.Write) != 0)
                {
                    AcceptOrConnectOperation connectTail;
                    SendReceiveOperation sendTail;
                    lock (_queueLock)
                    {
                        connectTail = _acceptOrConnectQueue.Tail as ConnectOperation;
                        _acceptOrConnectQueue.State = State.Set;

                        sendTail = _sendQueue.Tail;
                        _sendQueue.State = State.Set;
                    }

                    if (connectTail != null)
                    {
                        ConnectOperation op;
                        do
                        {
                            op = (ConnectOperation)_acceptOrConnectQueue.Head;
                            if (TryCompleteConnect(_fileDescriptor, op))
                            {
                                EndOperation(ref _acceptOrConnectQueue);

                                // The only situation in which we should see EISCONN when completing an
                                // async connect is if this earlier connect completed successfully:
                                // POSIX does not allow more than one outstanding async connect.
                                if (op.ErrorCode == SocketError.IsConnected)
                                {
                                    op.ErrorCode = SocketError.Success;
                                }
                                QueueCompletion(op);
                            }
                            break;
                        } while (op != connectTail);
                    }

                    if (sendTail != null)
                    {
                        SendReceiveOperation op;
                        do
                        {
                            op = _sendQueue.Head;
                            if (TryCompleteSendTo(_fileDescriptor, op))
                            {
                                EndOperation(ref _sendQueue);
                                QueueCompletion(op);
                            }
                            break;
                        } while (op != sendTail);
                    }
                }
            }
        }
    }
}
