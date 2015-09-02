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
    public partial class Socket
    {
        internal static IntPtr[] SocketListToFileDescriptorSet(IList socketList)
        {
            if (socketList == null || socketList.Count == 0)
            {
                return null;
            }
            IntPtr[] fileDescriptorSet = new IntPtr[socketList.Count + 1];
            fileDescriptorSet[0] = (IntPtr)socketList.Count;
            for (int current = 0; current < socketList.Count; current++)
            {
                if (!(socketList[current] is Socket))
                {
                    throw new ArgumentException(SR.Format(SR.net_sockets_select, socketList[current].GetType().FullName, typeof(System.Net.Sockets.Socket).FullName), "socketList");
                }
                fileDescriptorSet[current + 1] = ((Socket)socketList[current])._handle.DangerousGetHandle();
            }
            return fileDescriptorSet;
        }

        //
        // Transform the list socketList such that the only sockets left are those
        // with a file descriptor contained in the array "fileDescriptorArray"
        //
        internal static void SelectFileDescriptor(IList socketList, IntPtr[] fileDescriptorSet)
        {
            // Walk the list in order
            // Note that the counter is not necessarily incremented at each step;
            // when the socket is removed, advancing occurs automatically as the
            // other elements are shifted down.
            if (socketList == null || socketList.Count == 0)
            {
                return;
            }
            if ((int)fileDescriptorSet[0] == 0)
            {
                // no socket present, will never find any socket, remove them all
                socketList.Clear();
                return;
            }
            lock (socketList)
            {
                for (int currentSocket = 0; currentSocket < socketList.Count; currentSocket++)
                {
                    Socket socket = socketList[currentSocket] as Socket;
                    // Look for the file descriptor in the array
                    int currentFileDescriptor;
                    for (currentFileDescriptor = 0; currentFileDescriptor < (int)fileDescriptorSet[0]; currentFileDescriptor++)
                    {
                        if (fileDescriptorSet[currentFileDescriptor + 1] == socket._handle.DangerousGetHandle())
                        {
                            break;
                        }
                    }
                    if (currentFileDescriptor == (int)fileDescriptorSet[0])
                    {
                        // descriptor not found: remove the current socket and start again
                        socketList.RemoveAt(currentSocket--);
                    }
                }
            }
        }

        private Socket GetOrCreateAcceptSocket(Socket acceptSocket, bool checkDisconnected, string propertyName, out SafeCloseSocket handle)
        {
            // if a acceptSocket isn't specified, then we need to create it.
            if (acceptSocket == null)
            {
                acceptSocket = new Socket(_addressFamily, _socketType, _protocolType);
            }
            else
            {
                if (acceptSocket.m_RightEndPoint != null && (!checkDisconnected || !acceptSocket._isDisconnected))
                {
                    throw new InvalidOperationException(SR.Format(SR.net_sockets_namedmustnotbebound, propertyName));
                }
            }

            handle = acceptSocket._handle;
            return acceptSocket;
        }
    }
}
