// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Threading;

namespace System.Net.Sockets
{
    internal struct HandleTable<TValue>
    {
        private const int MaxSize = 65536;

        private int _tableSize;
        private int _allocatedHandleCount;
        private int[] _allocatedHandleBitmap;
        private ConcurrentDictionary<int, TValue> _allocatedHandles;
        private Func<TValue> _factory;

        public bool IsValid { get { return _factory != null; } }

        public HandleTable(int size, Func<TValue> factory)
        {
            Debug.Assert(size > 0);
            Debug.Assert(size <= MaxSize);
            Debug.Assert(factory != null);

            _tableSize = size;
            _allocatedHandleCount = 0;
            _allocatedHandleBitmap = new int[(size / sizeof(int)) + ((size % sizeof(int)) == 0 ? 0 : 1)];
            _allocatedHandles = new ConcurrentDictionary<int, TValue>();
            _factory = factory;
        }

        private int AllocateHandleId()
        {
            while (_allocatedHandleCount < _tableSize)
            {
                for (int i = 0; i < _allocatedHandleBitmap.Length; i++)
                {
                    int entry = _allocatedHandleBitmap[i];
                    while (entry != ~0)
                    {
                        // Find the first free handle in this block by looking for the first unset bit.
                        int bit;
                        for (bit = 0; bit < (sizeof(int) * 8) && (entry & 1) == 1; bit++, entry >>= 1)
                        {
                        }

                        int handleId = i * sizeof(int) + bit;
                        if (handleId >= _tableSize)
                        {
                            // This handle is outside the valid range--we must be in the final block.
                            // Retry.
                            break;
                        }

                        int bitMask = 1 << bit;
                        do
                        {
                            if (Interlocked.CompareExchange(ref _allocatedHandleBitmap[i], entry, entry | bitMask) == entry)
                            {
                                // We've claimed this handle; return the actual ID.
                                Interlocked.Increment(ref _allocatedHandleCount);
                                return handleId;
                            }

                            // The block was updated; retry.
                            entry = _allocatedHandleBitmap[i];
                        } while ((entry & bitMask) == 0);

                        // We lost the race to claim our handle. Retry.
                    }

                    // There are no more free handles in this block. Move on to the next.
                }
            }

            // If we got here, we're out of handles.
            return -1;
        }

        private void FreeHandleId(int handleId)
        {
            int block = handleId / sizeof(int);
            if (block < 0 || block >= _allocatedHandleBitmap.Length)
            {
                return;
            }

            int bit = handleId % sizeof(int);
            int bitMask = ~(1 << bit);
            int entry;
            do
            {
                entry = _allocatedHandleBitmap[block];
                Debug.Assert((entry & ~bitMask) == 1);
            } while (Interlocked.CompareExchange(ref _allocatedHandleBitmap[block], entry, entry & bitMask) != entry);

            Interlocked.Decrement(ref _allocatedHandleCount);
        }

        public bool TryGetValue(int handleId, out TValue value)
        {
            return _allocatedHandles.TryGetValue(handleId, out value);
        }

        public int AllocateHandle(out TValue value)
        {
            int handleId = AllocateHandleId();
            if (handleId == -1)
            {
                value = default(TValue);
                return handleId;
            }

            value = _factory();
            bool added = _allocatedHandles.TryAdd(handleId, value);
            Debug.Assert(added);

            return handleId;
        }

        public void FreeHandle(int handleId)
        {
            TValue unused;
            bool removed = _allocatedHandles.TryRemove(handleId, out unused);
            Debug.Assert(removed);
            FreeHandleId(handleId);
        }
    }
}
