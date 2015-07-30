﻿namespace NCLTest.Sockets
{
    using CoreFXTestLibrary;
    using System;
    using System.IO;
    using System.Net;
    using System.Net.Sockets;
    using System.Threading;
    using NCLTest.Common;

    [TestClass]
    public class SendPacketsAsync
    {
        private const int TestPortBase = 8100;

        private IPEndPoint Server = new IPEndPoint(IPAddress.IPv6Loopback, 8080); 
        // In the current directory
        private const string TestFileName = "NCLTest.Socket.SendPacketsAsync.testpayload";
        private static int TestFileSize = 1024;
        
        #region Additional test attributes

        public SendPacketsAsync()
        {
            // Workaround for 916993
            ClassInitialize();
        }

        [TestInitialize]
        public void ClassInitialize()
        {
            byte[] buffer = new byte[TestFileSize];

            for (int i = 0; i < TestFileSize; i++)
            {
                buffer[i] = (byte)(i % 255);
            }

            try
            {
                Console.WriteLine("Creating file {0} with size: {1}", TestFileName, TestFileSize);
                using (FileStream fs = new FileStream(TestFileName, FileMode.CreateNew))
                {
                    fs.Write(buffer, 0, buffer.Length);
                }
            }
            catch (IOException)
            {
                // Test payload file already exists.
                Console.WriteLine("Payload file exists: {0}", TestFileName);
            }
        }

        #endregion Additional test attributes


        #region Basic Arguments

        [TestMethod]
        public void Disposed_Throw()
        {
            try
            {
                using (SocketTestServer.SocketTestServerFactory(Server))
                {
                    using (Socket sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp))
                    {
                        sock.Connect(Server);
                        sock.Dispose();

                        sock.SendPacketsAsync(new SocketAsyncEventArgs());
                    }
                }
                Assert.Fail("Expected ObjectDisposedException");
            }
            catch (ObjectDisposedException)
            {
                // expected
                return;
            }
        }

        [TestMethod]
        public void NullArgs_Throw()
        {
            try
            {
                using (SocketTestServer.SocketTestServerFactory(Server))
                {
                    using (Socket sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp))
                    {
                        sock.Connect(Server);

                        sock.SendPacketsAsync(null);
                    }
                }
                Assert.Fail("Expected NullReferenceException");
            }
            catch (ArgumentNullException ex)
            {
                // expected
                Assert.AreEqual("e", ex.ParamName);
                return;
            }
        }

        [TestMethod]
        public void NotConnected_Throw()
        {
            try
            {
                Socket socket = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                // Needs to be connected before send
                socket.SendPacketsAsync(new SocketAsyncEventArgs());
                Assert.Fail("Expected NotSupportedException");
            }
            catch (ArgumentNullException ex)
            {
                // expected
                Assert.AreEqual("e.SendPacketsElements", ex.ParamName);
                return;
            }
        }

        [TestMethod]
        public void NullList_Throws()
        {
            try
            {
                SendPackets((SendPacketsElement[])null, SocketError.Success, 0);
                Assert.Fail("Expected NullReferenceException");
            }
            catch (ArgumentNullException ex)
            {
                // expected
                Assert.AreEqual("e.SendPacketsElements", ex.ParamName);
                return;
            }
        }

        [TestMethod]
        public void NullElement_Ignored()
        {
            SendPackets((SendPacketsElement)null, 0);
        }

        [TestMethod]
        public void EmptyList_Ignored()
        {
            SendPackets(new SendPacketsElement[0], SocketError.Success, 0);
        }

        [TestMethod]
        public void SocketAsyncEventArgs_DefaultSendSize_0()
        {
            SocketAsyncEventArgs args = new SocketAsyncEventArgs();
            Assert.AreEqual(0, args.SendPacketsSendSize);
        }

        #endregion Basic Arguments

        #region Buffers

        [TestMethod]
        public void NormalBuffer_Success()
        {
            SendPackets(new SendPacketsElement(new byte[10]), 10);
        }

        [TestMethod]
        public void NormalBufferRange_Success()
        {
            SendPackets(new SendPacketsElement(new byte[10], 5, 5), 5);
        }

        [TestMethod]
        public void EmptyBuffer_Ignored()
        {
            SendPackets(new SendPacketsElement(new byte[0]), 0);
        }

        [TestMethod]
        public void BufferZeroCount_Ignored()
        {
            SendPackets(new SendPacketsElement(new byte[10], 4, 0), 0);
        }

        [TestMethod]
        public void BufferMixedBuffers_ZeroCountBufferIgnored()
        {
            SendPacketsElement[] elements = new SendPacketsElement[] 
            {
                new SendPacketsElement(new byte[10], 4, 0), // Ignored
                new SendPacketsElement(new byte[10], 4, 4),
                new SendPacketsElement(new byte[10], 0, 4)
            };
            SendPackets(elements, SocketError.Success, 8);
        }

        [TestMethod]
        public void BufferZeroCountThenNormal_ZeroCountIgnored()
        {
            TestRequirements.CheckIPv6Support();

            EventWaitHandle completed = new ManualResetEvent(false);

            using (SocketTestServer.SocketTestServerFactory(Server))
            {
                using (Socket sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp))
                {
                    sock.Connect(Server);
                    using (SocketAsyncEventArgs args = new SocketAsyncEventArgs())
                    {
                        args.Completed += OnCompleted;
                        args.UserToken = completed;

                        // First do an empty send, ignored
                        args.SendPacketsElements = new SendPacketsElement[]
                        {
                            new SendPacketsElement(new byte[5], 3, 0)   
                        };

                        if (sock.SendPacketsAsync(args))
                        {
                            Assert.IsTrue(completed.WaitOne(500), "Timed out");
                        }
                        Assert.AreEqual(SocketError.Success, args.SocketError);
                        Assert.AreEqual(0, args.BytesTransferred);

                        completed.Reset();
                        // Now do a real send
                        args.SendPacketsElements = new SendPacketsElement[]
                        {
                            new SendPacketsElement(new byte[5], 1, 4)   
                        };

                        if (sock.SendPacketsAsync(args))
                        {
                            Assert.IsTrue(completed.WaitOne(500), "Timed out");
                        }
                        Assert.AreEqual(SocketError.Success, args.SocketError);
                        Assert.AreEqual(4, args.BytesTransferred);
                    }
                }
            }
        }

        #endregion Buffers

        #region Files

        [TestMethod]
        public void SendPacketsElement_EmptyFileName_Throws()
        {
            try
            {
                // Existence is validated on send
                SendPackets(new SendPacketsElement(String.Empty), 0);
                Assert.Fail("Expected ArgumentException");
            }
            catch (ArgumentException)
            {
                // expected
                return;
            }
        }

        [TestMethod]
        public void SendPacketsElement_BlankFileName_Throws()
        {
            try
            {
                // Existence is validated on send
                SendPackets(new SendPacketsElement(" \t  "), 0);
                Assert.Fail("Expected ArgumentException");
            }
            catch (ArgumentException)
            {
                // expected
                return;
            }
        }
        
        [TestMethod]
        public void SendPacketsElement_BadCharactersFileName_Throws()
        {
            try
            {
                // Existence is validated on send
                SendPackets(new SendPacketsElement("blarkd@dfa?/sqersf"), 0);
                Assert.Fail("Expected ArgumentException");
            }
            catch (ArgumentException)
            {
                // expected
                return;
            }
        }

        [TestMethod]
        public void SendPacketsElement_MissingDirectoryName_Throws()
        {
            try
            {
                // Existence is validated on send
                SendPackets(new SendPacketsElement(@"nodir\nofile"), 0);
                Assert.Fail("Expected DirectoryNotFoundException");
            }
            catch (DirectoryNotFoundException)
            {
                // expected
                return;
            }
        }

        [TestMethod]
        public void SendPacketsElement_MissingFile_Throws()
        {
            try
            {
                // Existence is validated on send
                SendPackets(new SendPacketsElement("DoesntExit"), 0);
                Assert.Fail("Expected FileNotFoundException");
            }
            catch (FileNotFoundException)
            {
                // expected
                return;
            }
        }

        [TestMethod]
        public void SendPacketsElement_File_Success()
        {
            SendPackets(new SendPacketsElement(TestFileName), TestFileSize); // Whole File
        }

        [TestMethod]
        public void SendPacketsElement_FileZeroCount_Success()
        {
            SendPackets(new SendPacketsElement(TestFileName, 0, 0), TestFileSize);  // Whole File
        }

        [TestMethod]
        public void SendPacketsElement_FilePart_Success()
        {
            SendPackets(new SendPacketsElement(TestFileName, 10, 20), 20);
        }

        [TestMethod]
        public void SendPacketsElement_FileMultiPart_Success()
        {
            SendPacketsElement[] elements = new SendPacketsElement[] 
            {
                new SendPacketsElement(TestFileName, 10, 20),
                new SendPacketsElement(TestFileName, 30, 10),
                new SendPacketsElement(TestFileName, 0, 10),
            };
            SendPackets(elements, SocketError.Success, 40);
        }

        [TestMethod]
        public void SendPacketsElement_FileLargeOffset_Throws()
        {
            // Length is validated on Send
            SendPackets(new SendPacketsElement(TestFileName, 11000, 1), SocketError.InvalidArgument, 0);
        }

        [TestMethod]
        public void SendPacketsElement_FileLargeCount_Throws()
        {
            // Length is validated on Send
            SendPackets(new SendPacketsElement(TestFileName, 5, 10000), SocketError.InvalidArgument, 0);
        }

        #endregion Files

        #region GC Finalizer test
        // This test assumes sequential execution of tests and that it is going to be executed after other tests
        // that used Sockets. 
        [TestMethod]
        public void TestFinalizers()
        {
            // Making several passes through the FReachable list.
            for (int i = 0; i < 3; i++)
            {
                GC.Collect();
                GC.WaitForPendingFinalizers();
            }
        }
        #endregion 

        #region Helpers

        private void SendPackets(SendPacketsElement element, int bytesExpected)
        {
            SendPackets(new SendPacketsElement[] { element }, SocketError.Success, bytesExpected);
        }

        private void SendPackets(SendPacketsElement element, SocketError expectedResut, int bytesExpected)
        {
            SendPackets(new SendPacketsElement[] { element }, expectedResut, bytesExpected);
        }

        private void SendPackets(SendPacketsElement[] elements, SocketError expectedResut, int bytesExpected)
        {
            TestRequirements.CheckIPv6Support();

            EventWaitHandle completed = new ManualResetEvent(false);

            using (SocketTestServer.SocketTestServerFactory(Server))
            {
                using (Socket sock = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp))
                {
                    sock.Connect(Server);
                    using (SocketAsyncEventArgs args = new SocketAsyncEventArgs())
                    {
                        args.Completed += OnCompleted;
                        args.UserToken = completed;
                        args.SendPacketsElements = elements;

                        if (sock.SendPacketsAsync(args))
                        {
                            Assert.IsTrue(completed.WaitOne(500), "Timed out");
                        }
                        Assert.AreEqual(expectedResut, args.SocketError);
                        Assert.AreEqual(bytesExpected, args.BytesTransferred);
                    }
                }
            }
        }

        void OnCompleted(object sender, SocketAsyncEventArgs e)
        {
            EventWaitHandle handle = (EventWaitHandle)e.UserToken;
            handle.Set();
        }

        #endregion Helpers
    }
}