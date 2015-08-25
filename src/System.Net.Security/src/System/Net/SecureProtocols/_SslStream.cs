// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
/*++
Copyright (c) Microsoft Corporation

Module Name:

    _SslStream.cs

Abstract:
    Internal helper to support public SslStream class.
    It would be nice to make it a partial class file once compiler gets this supported

Author:
    Alexei Vopilov    22-Aug-2003

Revision History:
    22-Aug-2003 New design that has obsoleted SslClientStream and SslServerStream class

--*/

using System;
using System.IO;
using System.Security;
using System.Security.Principal;
using System.Threading;
using System.Collections.Generic;
using System.Net.Sockets;

namespace System.Net.Security
{
    //
    // This is a wrapping stream that does data encryption/decryption based on a successfully authenticated SSPI context.
    //
    internal class _SslStream
    {
        private static AsyncCallback _WriteCallback = new AsyncCallback(WriteCallback);
        private static AsyncProtocolCallback _ResumeAsyncReadCallback = new AsyncProtocolCallback(ResumeAsyncReadCallback);
        private static AsyncProtocolCallback _ReadHeaderCallback = new AsyncProtocolCallback(ReadHeaderCallback);
        private static AsyncProtocolCallback _ReadFrameCallback = new AsyncProtocolCallback(ReadFrameCallback);

        private const int PinnableReadBufferSize = 4096 * 4 + 32;         // We like to read in 16K chunks + headers
        private static PinnableBufferCache s_PinnableReadBufferCache = new PinnableBufferCache("System.Net.SslStream", PinnableReadBufferSize);
        private const int PinnableWriteBufferSize = 4096 + 1024;        // We like to write in 4K chunks + encryption overhead
        private static PinnableBufferCache s_PinnableWriteBufferCache = new PinnableBufferCache("System.Net.SslStream", PinnableWriteBufferSize);

        private SslState _SslState;
        private int _NestedWrite;
        private int _NestedRead;

        // never updated directly, special properties are used.  This is the read buffer
        private byte[] _InternalBuffer;
        private bool _InternalBufferFromPinnableCache;

        private byte[] _PinnableOutputBuffer;                        // Used for writes when we can do it. 
        private byte[] _PinnableOutputBufferInUse;                   // remembers what UNENCRYPTED buffer is using _PinnableOutputBuffer

        private int _InternalOffset;
        private int _InternalBufferCount;

        FixedSizeReader _Reader;

        internal _SslStream(SslState sslState)
        {
            if (PinnableBufferCacheEventSource.Log.IsEnabled())
            {
                PinnableBufferCacheEventSource.Log.DebugMessage1("CTOR: In System.Net._SslStream.SslStream", this.GetHashCode());
            }
            _SslState = sslState;
            _Reader = new FixedSizeReader(_SslState.InnerStream);
        }

        // if we have a read buffer from the pinnable cache, return it
        void FreeReadBuffer()
        {
            if (_InternalBufferFromPinnableCache)
            {
                s_PinnableReadBufferCache.FreeBuffer(_InternalBuffer);
                _InternalBufferFromPinnableCache = false;
            }
            _InternalBuffer = null;
        }

        ~_SslStream()
        {
            if (_InternalBufferFromPinnableCache)
            {
                if (PinnableBufferCacheEventSource.Log.IsEnabled())
                {
                    PinnableBufferCacheEventSource.Log.DebugMessage2("DTOR: In System.Net._SslStream.~SslStream Freeing Read Buffer", this.GetHashCode(), PinnableBufferCacheEventSource.AddressOfByteArray(_InternalBuffer));
                }
                FreeReadBuffer();
            }
            if (_PinnableOutputBuffer != null)
            {
                if (PinnableBufferCacheEventSource.Log.IsEnabled())
                {
                    PinnableBufferCacheEventSource.Log.DebugMessage2("DTOR: In System.Net._SslStream.~SslStream Freeing Write Buffer", this.GetHashCode(), PinnableBufferCacheEventSource.AddressOfByteArray(_PinnableOutputBuffer));
                }
                s_PinnableWriteBufferCache.FreeBuffer(_PinnableOutputBuffer);
            }
        }

        //
        // Some of the Public Stream class contract
        //
        //
        //
        internal int Read(byte[] buffer, int offset, int count)
        {
            return ProcessRead(buffer, offset, count, null);
        }
        //
        //
        internal void Write(byte[] buffer, int offset, int count)
        {
            ProcessWrite(buffer, offset, count, null);
        }
        //
        //
        //
        // Internal implemenation
        //

        //
        //
        internal bool DataAvailable
        {
            get { return InternalBufferCount != 0; }
        }
        //
        //
        private byte[] InternalBuffer
        {
            get
            {
                return _InternalBuffer;
            }
        }
        //
        //
        private int InternalOffset
        {
            get
            {
                return _InternalOffset;
            }
        }
        //
        //
        private int InternalBufferCount
        {
            get
            {
                return _InternalBufferCount;
            }
        }
        //
        //
        private void DecrementInternalBufferCount(int decrCount)
        {
            _InternalOffset += decrCount;
            _InternalBufferCount -= decrCount;
        }
        //
        // This will set the internal offset to "curOffset" and ensure internal buffer.
        // If not enough, reallocate and copy up to "curOffset"
        //
        private void EnsureInternalBufferSize(int curOffset, int addSize)
        {
            if (_InternalBuffer == null || _InternalBuffer.Length < addSize + curOffset)
            {
                bool wasPinnable = _InternalBufferFromPinnableCache;
                byte[] saved = _InternalBuffer;

                int newSize = addSize + curOffset;
                if (newSize <= PinnableReadBufferSize)
                {
                    if (PinnableBufferCacheEventSource.Log.IsEnabled())
                    {
                        PinnableBufferCacheEventSource.Log.DebugMessage2("In System.Net._SslStream.EnsureInternalBufferSize IS pinnable", this.GetHashCode(), newSize);
                    }
                    _InternalBufferFromPinnableCache = true;
                    _InternalBuffer = s_PinnableReadBufferCache.AllocateBuffer();
                }
                else
                {
                    if (PinnableBufferCacheEventSource.Log.IsEnabled())
                    {
                        PinnableBufferCacheEventSource.Log.DebugMessage2("In System.Net._SslStream.EnsureInternalBufferSize NOT pinnable", this.GetHashCode(), newSize);
                    }
                    _InternalBufferFromPinnableCache = false;
                    _InternalBuffer = new byte[newSize];
                }

                if (saved != null && curOffset != 0)
                {
                    Buffer.BlockCopy(saved, 0, _InternalBuffer, 0, curOffset);
                }

                if (wasPinnable)
                {
                    s_PinnableReadBufferCache.FreeBuffer(saved);
                }
            }
            _InternalOffset = curOffset;
            _InternalBufferCount = curOffset + addSize;
        }
        //
        // Validates user parameteres for all Read/Write methods
        //
        private void ValidateParameters(byte[] buffer, int offset, int count)
        {
            if (buffer == null)
                throw new ArgumentNullException("buffer");

            if (offset < 0)
                throw new ArgumentOutOfRangeException("offset");

            if (count < 0)
                throw new ArgumentOutOfRangeException("count");

            if (count > buffer.Length - offset)
                throw new ArgumentOutOfRangeException("count", SR.net_offset_plus_count);
        }
        //
        // Combined sync/async write method. For sync case asyncRequest==null
        //
        private void ProcessWrite(byte[] buffer, int offset, int count, AsyncProtocolRequest asyncRequest)
        {
            ValidateParameters(buffer, offset, count);

            if (Interlocked.Exchange(ref _NestedWrite, 1) == 1)
            {
                throw new NotSupportedException(SR.Format(SR.net_io_invalidnestedcall, (asyncRequest != null ? "BeginWrite" : "Write"), "write"));
            }

            bool failed = false;
            try
            {
                StartWriting(buffer, offset, count, asyncRequest);
            }
            catch (Exception e)
            {
                _SslState.FinishWrite();

                failed = true;
                if (e is IOException)
                {
                    throw;
                }
                throw new IOException(SR.net_io_write, e);
            }
            finally
            {
                if (asyncRequest == null || failed)
                {
                    _NestedWrite = 0;
                }
            }
        }

        //
        private void StartWriting(byte[] buffer, int offset, int count, AsyncProtocolRequest asyncRequest)
        {
            if (asyncRequest != null)
            {
                asyncRequest.SetNextRequest(buffer, offset, count, _ResumeAsyncWriteCallback);
            }

            // We loop to this method from the callback
            // If the last chunk was just completed from async callback (count < 0), we complete user request
            if (count >= 0)
            {
                byte[] outBuffer = null;
                if (_PinnableOutputBufferInUse == null)                // The output buffer is not in use
                {
                    if (_PinnableOutputBuffer == null)                // Create one if needed
                    {
                        _PinnableOutputBuffer = s_PinnableWriteBufferCache.AllocateBuffer();
                    }
                    _PinnableOutputBufferInUse = buffer;        // put it in use
                    outBuffer = _PinnableOutputBuffer;
                    if (PinnableBufferCacheEventSource.Log.IsEnabled())
                    {
                        PinnableBufferCacheEventSource.Log.DebugMessage3("In System.Net._SslStream.StartWriting Trying Pinnable", this.GetHashCode(), count, PinnableBufferCacheEventSource.AddressOfByteArray(outBuffer));
                    }
                }
                else
                {
                    if (PinnableBufferCacheEventSource.Log.IsEnabled())
                    {
                        PinnableBufferCacheEventSource.Log.DebugMessage2("In System.Net._SslStream.StartWriting BufferInUse", this.GetHashCode(), count);
                    }
                }

                do
                {
                    // request a write IO slot
                    if (_SslState.CheckEnqueueWrite(asyncRequest))
                    {
                        // operation is async and has been queued, return.
                        return;
                    }

                    int chunkBytes = Math.Min(count, _SslState.MaxDataSize);
                    int encryptedBytes;
                    Interop.SecurityStatus errorCode = _SslState.EncryptData(buffer, offset, chunkBytes, ref outBuffer, out encryptedBytes);
                    if (errorCode != Interop.SecurityStatus.OK)
                    {
                        //CONSIDER: should we support re-handshake status?
                        ProtocolToken message = new ProtocolToken(null, errorCode);
                        throw new IOException(SR.net_io_encrypt, message.GetException());
                    }

                    if (PinnableBufferCacheEventSource.Log.IsEnabled())
                    {
                        PinnableBufferCacheEventSource.Log.DebugMessage3("In System.Net._SslStream.StartWriting Got Encrypted Buffer",
                            this.GetHashCode(), encryptedBytes, PinnableBufferCacheEventSource.AddressOfByteArray(outBuffer));
                    }
                    if (asyncRequest != null)
                    {
                        // prepare for the next request
                        asyncRequest.SetNextRequest(buffer, offset + chunkBytes, count - chunkBytes, _ResumeAsyncWriteCallback);
                        IAsyncResult ar = _SslState.InnerStreamAPM.BeginWrite(outBuffer, 0, encryptedBytes, _WriteCallback, asyncRequest);
                        if (!ar.CompletedSynchronously)
                        {
                            return;
                        }
                        _SslState.InnerStreamAPM.EndWrite(ar);
                    }
                    else
                    {
                        _SslState.InnerStream.Write(outBuffer, 0, encryptedBytes);
                    }
                    offset += chunkBytes;
                    count -= chunkBytes;

                    // release write IO slot
                    _SslState.FinishWrite();
                } while (count != 0);
            }

            if (asyncRequest != null)
            {
                asyncRequest.CompleteUser();
            }

            if (buffer == _PinnableOutputBufferInUse)                // Did we put it in use?
            {
                // Then free it 
                _PinnableOutputBufferInUse = null;
                if (PinnableBufferCacheEventSource.Log.IsEnabled())
                {
                    PinnableBufferCacheEventSource.Log.DebugMessage1("In System.Net._SslStream.StartWriting Freeing buffer.", this.GetHashCode());
                }
            }
        }

        //
        // Combined sync/async read method. For sync requet asyncRequest==null
        // There is a little overheader because we need to pass buffer/offset/count used only in sync.
        // Still the benefit is that we have a common sync/async code path.
        //
        private int ProcessRead(byte[] buffer, int offset, int count, AsyncProtocolRequest asyncRequest)
        {
            ValidateParameters(buffer, offset, count);

            if (Interlocked.Exchange(ref _NestedRead, 1) == 1)
            {
                throw new NotSupportedException(SR.Format(SR.net_io_invalidnestedcall, (asyncRequest != null ? "BeginRead" : "Read"), "read"));
            }

            bool failed = false;
            try
            {
                int copyBytes;
                if (InternalBufferCount != 0)
                {
                    copyBytes = InternalBufferCount > count ? count : InternalBufferCount;
                    if (copyBytes != 0)
                    {
                        Buffer.BlockCopy(InternalBuffer, InternalOffset, buffer, offset, copyBytes);
                        DecrementInternalBufferCount(copyBytes);
                    }
                    if (asyncRequest != null)
                    {
                        asyncRequest.CompleteUser((object)copyBytes);
                    }
                    return copyBytes;
                }
                // going into real IO
                return StartReading(buffer, offset, count, asyncRequest);
            }
            catch (Exception e)
            {
                _SslState.FinishRead(null);
                failed = true;
                if (e is IOException)
                {
                    throw;
                }
                throw new IOException(SR.net_io_read, e);
            }
            finally
            {
                // if sync request or exception
                if (asyncRequest == null || failed)
                {
                    _NestedRead = 0;
                }
            }
        }
        //
        // To avoid recursion when decrypted 0 bytes this method will loop until a decrypted result at least 1 byte.
        //
        private int StartReading(byte[] buffer, int offset, int count, AsyncProtocolRequest asyncRequest)
        {
            int result = 0;

            GlobalLog.Assert(InternalBufferCount == 0, "SslStream::StartReading()|Previous frame was not consumed. InternalBufferCount:{0}", InternalBufferCount);

            do
            {
                if (asyncRequest != null)
                {
                    asyncRequest.SetNextRequest(buffer, offset, count, _ResumeAsyncReadCallback);
                }
                int copyBytes = _SslState.CheckEnqueueRead(buffer, offset, count, asyncRequest);
                if (copyBytes == 0)
                {
                    //queued but not completed!
                    return 0;
                }

                if (copyBytes != -1)
                {
                    if (asyncRequest != null)
                    {
                        asyncRequest.CompleteUser((object)copyBytes);
                    }
                    return copyBytes;
                }
            }
            // When we read -1 bytes means we have decrypted 0 bytes or rehandshaking, need looping.
            while ((result = StartFrameHeader(buffer, offset, count, asyncRequest)) == -1);

            return result;
        }
        //
        // Need read frame size first
        //
        private int StartFrameHeader(byte[] buffer, int offset, int count, AsyncProtocolRequest asyncRequest)
        {
            int readBytes = 0;

            //
            // Always pass InternalBuffer for SSPI "in place" decryption.
            // A user buffer can be shared by many threads in that case decryption/integrity check may fail cause of data corruption.
            //

            // reset internal buffer for a new frame
            EnsureInternalBufferSize(0, SecureChannel.ReadHeaderSize);

            if (asyncRequest != null)
            {
                asyncRequest.SetNextRequest(InternalBuffer, 0, SecureChannel.ReadHeaderSize, _ReadHeaderCallback);
                _Reader.AsyncReadPacket(asyncRequest);
                if (!asyncRequest.MustCompleteSynchronously)
                {
                    return 0;
                }
                readBytes = asyncRequest.Result;
            }
            else
            {
                readBytes = _Reader.ReadPacket(InternalBuffer, 0, SecureChannel.ReadHeaderSize);
            }
            return StartFrameBody(readBytes, buffer, offset, count, asyncRequest);
        }
        //
        //
        //
        private int StartFrameBody(int readBytes, byte[] buffer, int offset, int count, AsyncProtocolRequest asyncRequest)
        {
            if (readBytes == 0)
            {
                //EOF
                //Reset the buffer as we did not read anything into it
                DecrementInternalBufferCount(InternalBufferCount);
                if (asyncRequest != null)
                {
                    asyncRequest.CompleteUser((object)0);
                }
                return 0;
            }

            // Now readBytes is a payload size
            readBytes = _SslState.GetRemainingFrameSize(InternalBuffer, readBytes);
            //
            // And the payload size must be >= 0
            //
            if (readBytes < 0)
            {
                throw new IOException(SR.net_frame_read_size);
            }

            EnsureInternalBufferSize(SecureChannel.ReadHeaderSize, readBytes);

            if (asyncRequest != null) //Async
            {
                asyncRequest.SetNextRequest(InternalBuffer, SecureChannel.ReadHeaderSize, readBytes, _ReadFrameCallback);

                _Reader.AsyncReadPacket(asyncRequest);

                if (!asyncRequest.MustCompleteSynchronously)
                {
                    return 0;
                }
                readBytes = asyncRequest.Result;
            }
            else //Sync
            {
                readBytes = _Reader.ReadPacket(InternalBuffer, SecureChannel.ReadHeaderSize, readBytes);
            }
            return ProcessFrameBody(readBytes, buffer, offset, count, asyncRequest);
        }
        //
        // readBytes == SSL Data Payload size on input or 0 on EOF
        //
        private int ProcessFrameBody(int readBytes, byte[] buffer, int offset, int count, AsyncProtocolRequest asyncRequest)
        {
            if (readBytes == 0)
            {
                // Eof
                throw new IOException(SR.net_io_eof);
            }

            //Set readBytes to total number of received bytes
            readBytes += SecureChannel.ReadHeaderSize;

            //Decrypt into internal buffer, change "readBytes" to count now _Decrypted Bytes_
            int data_offset = 0;

            Interop.SecurityStatus errorCode = _SslState.DecryptData(InternalBuffer, ref data_offset, ref readBytes);

            if (errorCode != Interop.SecurityStatus.OK)
            {
                byte[] extraBuffer = null;
                if (readBytes != 0)
                {
                    extraBuffer = new byte[readBytes];
                    Buffer.BlockCopy(InternalBuffer, data_offset, extraBuffer, 0, readBytes);
                }
                // Reset internal buffer count
                DecrementInternalBufferCount(InternalBufferCount);
                return ProcessReadErrorCode(errorCode, buffer, offset, count, asyncRequest, extraBuffer);
            }


            if (readBytes == 0 && count != 0)
            {
                //Read again since remote side has sent encrypted 0 bytes
                DecrementInternalBufferCount(InternalBufferCount);
                return -1;
            }

            // Decrypted data start from "data_offset" offset, the total count can be shrinked after decryption
            EnsureInternalBufferSize(0, data_offset + readBytes);
            DecrementInternalBufferCount(data_offset);

            if (readBytes > count)
            {
                readBytes = count;
            }
            Buffer.BlockCopy(InternalBuffer, InternalOffset, buffer, offset, readBytes);

            // This will adjust both the remaining internal buffer count and the offset
            DecrementInternalBufferCount(readBytes);

            _SslState.FinishRead(null);
            if (asyncRequest != null)
            {
                asyncRequest.CompleteUser((object)readBytes);
            }

            return readBytes;
        }
        //
        // Codes we process (Anything else - fail)
        //
        // - SEC_I_RENEGOTIATE
        //
        private int ProcessReadErrorCode(Interop.SecurityStatus errorCode, byte[] buffer, int offset, int count, AsyncProtocolRequest asyncRequest, byte[] extraBuffer)
        {
            // ERROR - examine what kind
            ProtocolToken message = new ProtocolToken(null, errorCode);

            GlobalLog.Print("SecureChannel#" + Logging.HashString(this) + "::***Processing an error Status = " + message.Status.ToString());

            if (message.Renegotiate)
            {
                _SslState.ReplyOnReAuthentication(extraBuffer);
                // loop on read
                return -1;
            }
            if (message.CloseConnection)
            {
                _SslState.FinishRead(null);
                if (asyncRequest != null)
                {
                    asyncRequest.CompleteUser((object)0);
                }
                return 0;
            }
            // Otherwise bail out.
            throw new IOException(SR.net_io_decrypt, message.GetException());
        }
        //
        //
        //
        private static void WriteCallback(IAsyncResult transportResult)
        {
            if (transportResult.CompletedSynchronously)
            {
                return;
            }

            GlobalLog.Assert(transportResult.AsyncState is AsyncProtocolRequest, "SslStream::WriteCallback|State type is wrong, expected AsyncProtocolRequest.");
            AsyncProtocolRequest asyncRequest = (AsyncProtocolRequest)transportResult.AsyncState;

            _SslStream sslStream = (_SslStream)asyncRequest.AsyncObject;
            try
            {
                sslStream._SslState.InnerStreamAPM.EndWrite(transportResult);
                sslStream._SslState.FinishWrite();

                if (asyncRequest.Count == 0)
                {
                    // this was the last chunk
                    asyncRequest.Count = -1;
                }
                sslStream.StartWriting(asyncRequest.Buffer, asyncRequest.Offset, asyncRequest.Count, asyncRequest);
            }
            catch (Exception e)
            {
                if (asyncRequest.IsUserCompleted)
                {
                    // This will throw on a worker thread.
                    throw;
                }
                sslStream._SslState.FinishWrite();
                asyncRequest.CompleteWithError(e);
            }
        }

        //
        // This is used in a rare situation when async Read is resumed from completed handshake
        //
        private static void ResumeAsyncReadCallback(AsyncProtocolRequest request)
        {
            try
            {
                ((_SslStream)request.AsyncObject).StartReading(request.Buffer, request.Offset, request.Count, request);
            }
            catch (Exception e)
            {
                if (request.IsUserCompleted)
                {
                    // This will throw on a worker thread.
                    throw;
                }
                ((_SslStream)request.AsyncObject)._SslState.FinishRead(null);
                request.CompleteWithError(e);
            }
        }

        //
        //
        private static void ReadHeaderCallback(AsyncProtocolRequest asyncRequest)
        {
            // Async ONLY completion
            try
            {
                _SslStream sslStream = (_SslStream)asyncRequest.AsyncObject;
                BufferAsyncResult bufferResult = (BufferAsyncResult)asyncRequest.UserAsyncResult;
                if (-1 == sslStream.StartFrameBody(asyncRequest.Result, bufferResult.Buffer, bufferResult.Offset, bufferResult.Count, asyncRequest))
                {
                    // in case we decrypted 0 bytes start another reading.
                    sslStream.StartReading(bufferResult.Buffer, bufferResult.Offset, bufferResult.Count, asyncRequest);
                }
            }
            catch (Exception e)
            {
                if (asyncRequest.IsUserCompleted)
                {
                    // This will throw on a worker thread.
                    throw;
                }
                asyncRequest.CompleteWithError(e);
            }
        }
        //
        //
        private static void ReadFrameCallback(AsyncProtocolRequest asyncRequest)
        {
            // Async ONLY completion
            try
            {
                _SslStream sslStream = (_SslStream)asyncRequest.AsyncObject;
                BufferAsyncResult bufferResult = (BufferAsyncResult)asyncRequest.UserAsyncResult;
                if (-1 == sslStream.ProcessFrameBody(asyncRequest.Result, bufferResult.Buffer, bufferResult.Offset, bufferResult.Count, asyncRequest))
                {
                    // in case we decrypted 0 bytes start another reading.
                    sslStream.StartReading(bufferResult.Buffer, bufferResult.Offset, bufferResult.Count, asyncRequest);
                }
            }
            catch (Exception e)
            {
                if (asyncRequest.IsUserCompleted)
                {
                    // This will throw on a worker thread.
                    throw;
                }
                asyncRequest.CompleteWithError(e);
            }
        }

        private class SplitWriteAsyncProtocolRequest : AsyncProtocolRequest
        {
            internal Interop.SplitWritesState SplitWritesState;  // If one buffer is no enough (such as for multiple writes)

            internal SplitWriteAsyncProtocolRequest(LazyAsyncResult userAsyncResult) : base(userAsyncResult)
            {
            }

            internal void SetNextRequest(Interop.SplitWritesState splitWritesState, AsyncProtocolCallback callback)
            {
                SplitWritesState = splitWritesState;
                SetNextRequest(null, 0, 0, callback);
            }
        }
        //
    }
}
