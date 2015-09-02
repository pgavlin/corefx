// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using System.Diagnostics.Contracts;

namespace System.Net.Sockets
{
    // class that wraps the semantics of a winsock TRANSMIT_PACKETS_ELEMENTS struct
    public class SendPacketsElement
    {
        internal string m_FilePath;
        internal byte[] m_Buffer;
        internal int m_Offset;
        internal int m_Count;
        internal Interop.Winsock.TransmitPacketsElementFlags m_Flags;

        // hide default constructor
        private SendPacketsElement() { }

        // constructors for file elements
        public SendPacketsElement(string filepath) :
            this(filepath, 0, 0, false)
        { }

        public SendPacketsElement(string filepath, int offset, int count) :
            this(filepath, offset, count, false)
        { }

        public SendPacketsElement(string filepath, int offset, int count, bool endOfPacket)
        {
            // We will validate if the file exists on send
            if (filepath == null)
            {
                throw new ArgumentNullException("filepath");
            }
            // The native API will validate the file length on send
            if (offset < 0)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (count < 0)
            {
                throw new ArgumentOutOfRangeException("count");
            }
            Contract.EndContractBlock();

            Initialize(filepath, null, offset, count, Interop.Winsock.TransmitPacketsElementFlags.File,
                endOfPacket);
        }

        // constructors for buffer elements
        public SendPacketsElement(byte[] buffer) :
            this(buffer, 0, (buffer != null ? buffer.Length : 0), false)
        { }

        public SendPacketsElement(byte[] buffer, int offset, int count) :
            this(buffer, offset, count, false)
        { }

        public SendPacketsElement(byte[] buffer, int offset, int count, bool endOfPacket)
        {
            if (buffer == null)
            {
                throw new ArgumentNullException("buffer");
            }
            if (offset < 0 || offset > buffer.Length)
            {
                throw new ArgumentOutOfRangeException("offset");
            }
            if (count < 0 || count > (buffer.Length - offset))
            {
                throw new ArgumentOutOfRangeException("count");
            }
            Contract.EndContractBlock();

            Initialize(null, buffer, offset, count, Interop.Winsock.TransmitPacketsElementFlags.Memory,
                endOfPacket);
        }

        private void Initialize(string filePath, byte[] buffer, int offset, int count,
            Interop.Winsock.TransmitPacketsElementFlags flags, bool endOfPacket)
        {
            m_FilePath = filePath;
            m_Buffer = buffer;
            m_Offset = offset;
            m_Count = count;
            m_Flags = flags;
            if (endOfPacket)
            {
                m_Flags |= Interop.Winsock.TransmitPacketsElementFlags.EndOfPacket;
            }
        }

        // Filename property
        public string FilePath
        {
            get { return m_FilePath; }
        }

        // Buffer property
        public byte[] Buffer
        {
            get { return m_Buffer; }
        }

        // Count property
        public int Count
        {
            get { return m_Count; }
        }

        // Offset property
        public int Offset
        {
            get { return m_Offset; }
        }

        // EndOfPacket property
        public bool EndOfPacket
        {
            get { return (m_Flags & Interop.Winsock.TransmitPacketsElementFlags.EndOfPacket) != 0; }
        }
    }
}
