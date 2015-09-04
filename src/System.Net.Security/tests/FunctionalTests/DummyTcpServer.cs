using System.IO;
using System.Net.Sockets;
using System.Net.Test.Common;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Xunit;

namespace System.Net.Security.Tests
{ 
    // Callback method that is called when the server receives data from a connected client.  
    // The callback method should return a byte array and the number of bytes to send from that array.
    public delegate void DummyTcpServerReceiveCallback(byte[] bufferReceived, int bytesReceived, Stream stream);

    // Provides a dummy TCP/IP server that accepts connections and supports SSL/TLS.
    // It normally echos data received but can be configured to write a byte array 
    // specified by a callback method.
    public class DummyTcpServer : IDisposable
    {
        private VerboseTestLogging _log;
        private TcpListener listener;
        private bool useSsl;
        private SslProtocols sslProtocols = SslProtocols.Tls12 | SslProtocols.Tls11 | SslProtocols.Tls;
        private EncryptionPolicy sslEncryptionPolicy;
        private IPEndPoint remoteEndPoint;
        private DummyTcpServerReceiveCallback receiveCallback;

        private void StartListener(IPEndPoint endPoint)
        {
            listener = new TcpListener(endPoint);
            listener.Start(5);
            _log.WriteLine("Server {0} listening", endPoint.Address.ToString());
            listener.BeginAcceptTcpClient(OnAccept, null);
        }

        public DummyTcpServer(IPEndPoint endPoint) : this(endPoint, null)
        {
        }

        public DummyTcpServer(IPEndPoint endPoint, EncryptionPolicy? sslEncryptionPolicy)
        {
            _log = VerboseTestLogging.GetInstance();

            if (sslEncryptionPolicy != null)
            {
                this.remoteEndPoint = endPoint;
                this.useSsl = true;
                this.sslEncryptionPolicy = (EncryptionPolicy)sslEncryptionPolicy;
            }

            StartListener(endPoint);
        }

        public IPEndPoint RemoteEndPoint
        {
            get { return (IPEndPoint)listener.LocalEndpoint; }
        }

        public SslProtocols SslProtocols
        {
            get { return sslProtocols; }
            set { sslProtocols = value; }
        }

        protected DummyTcpServerReceiveCallback ReceiveCallback
        {
            get { return receiveCallback; }
            set { receiveCallback = value; }
        }

        public void Dispose()
        {
            Dispose(true);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                listener.Stop();
            }
        }

        protected virtual void OnClientAccepted(TcpClient client)
        {
        }

        private void OnAuthenticate(IAsyncResult result)
        {
            ClientState state = (ClientState)result.AsyncState;
            SslStream sslStream = (SslStream)state.Stream;

            try
            {
                sslStream.EndAuthenticateAsServer(result);
                _log.WriteLine("Server({0}) authenticated to client({1}) with encryption cipher: {2} {3}-bit strength",
                    state.TcpClient.Client.LocalEndPoint, state.TcpClient.Client.RemoteEndPoint, 
                    sslStream.CipherAlgorithm, sslStream.CipherStrength);

                // Start listening for data from the client connection
                sslStream.BeginRead(state.ReceiveBuffer, 0, state.ReceiveBuffer.Length, OnReceive, state);
            }
            catch (AuthenticationException authEx)
            {
                _log.WriteLine(
                    "Server({0}) disconnecting from client({1}) during authentication.  No shared SSL/TLS algorithm. ({2})",
                    state.TcpClient.Client.LocalEndPoint, 
                    state.TcpClient.Client.RemoteEndPoint,
                    authEx);
            }
            catch (Exception ex)
            {
                _log.WriteLine("Server({0}) disconnecting from client({1}) during authentication.  Exception: {2}",
                    state.TcpClient.Client.LocalEndPoint, state.TcpClient.Client.RemoteEndPoint, ex.Message);
            }
            finally
            {
                state.Dispose();
            }
        }

        private void OnAccept(IAsyncResult result)
        {
            TcpClient client = null;

            // Accept current connection
            try
            {
                client = listener.EndAcceptTcpClient(result);
            }
            catch
            {
            }

            // If we have a connection, then process it
            if (client != null)
            {
                OnClientAccepted(client);

                ClientState state;

                // Start authentication for SSL?
                if (useSsl)
                {
                    state = new ClientState(client, sslEncryptionPolicy);
                    _log.WriteLine("Server: starting SSL authentication.");


                    SslStream sslStream = null;
                    X509Certificate2 certificate = null;

                    var certCollection = new X509Certificate2Collection();
                    certCollection.Import(Path.Combine("TestData", "DummyTcpServer.pfx"));
                    
                    foreach (X509Certificate2 c in certCollection)
                    {
                        if (c.HasPrivateKey)
                        {
                            certificate = c;
                            break;
                        }
                    }

                    Assert.NotNull(certificate);

                    try
                    {
                        sslStream = (SslStream)state.Stream;

                        _log.WriteLine("Server: attempting to open SslStream.");
                        sslStream.BeginAuthenticateAsServer(certificate, false, sslProtocols, false, OnAuthenticate, state);
                    }
                    catch (Exception ex)
                    {
                        _log.WriteLine("Server: Exception: {0}", ex);

                        state.Dispose(); // close connection to client
                    }
                }
                else
                {
                    state = new ClientState(client);

                    // Start listening for data from the client connection
                    try
                    {
                        state.Stream.BeginRead(state.ReceiveBuffer, 0, state.ReceiveBuffer.Length, OnReceive, state);
                    }
                    catch
                    {
                    }
                }
            }

            // Listen for more client connections
            try
            {
                listener.BeginAcceptTcpClient(OnAccept, null);
            }
            catch
            {
            }
        }

        private void OnReceive(IAsyncResult result)
        {
            ClientState state = (ClientState)result.AsyncState;

            try
            {
                int bytesReceived = state.Stream.EndRead(result);
                if (bytesReceived == 0)
                {
                    state.Dispose();
                    return;
                }

                if (receiveCallback != null)
                {
                    receiveCallback(state.ReceiveBuffer, bytesReceived, state.Stream);
                }
                else
                {
                    // Echo back what we received
                    state.Stream.Write(state.ReceiveBuffer, 0, bytesReceived);
                }

                // Read more from client (asynchronous)
                state.Stream.BeginRead(state.ReceiveBuffer, 0, state.ReceiveBuffer.Length, OnReceive, state);
            }
            catch (IOException)
            {
                state.Dispose();
                return;
            }
            catch (SocketException)
            {
                state.Dispose();
                return;
            }
            catch (ObjectDisposedException)
            {
                state.Dispose();
                return;
            }
        }

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public static bool AlwaysValidServerCertificate(object sender, X509Certificate certificate, X509Chain chain, SslPolicyErrors sslPolicyErrors)
        {
            return true;  // allow everything
        }

        private class ClientState
        {
            private TcpClient tcpClient;
            private byte[] receiveBuffer;
            private bool useSsl;
            private SslStream sslStream;
            private bool closed;

            public ClientState(TcpClient client)
            {
                this.tcpClient = client;
                this.receiveBuffer = new byte[1024];
                this.useSsl = false;
                closed = false;
            }

            public ClientState(TcpClient client, EncryptionPolicy sslEncryptionPolicy)
            {
                this.tcpClient = client;
                this.receiveBuffer = new byte[1024];
                this.useSsl = true;
                sslStream = new SslStream(client.GetStream(), false, AlwaysValidServerCertificate, null, sslEncryptionPolicy);
                closed = false;
            }

            public void Dispose()
            {
                if (!closed)
                {
                    if (useSsl)
                    {
                        sslStream.Dispose();
                    }
                    tcpClient.Dispose();
                    closed = true;
                }
            }

            public TcpClient TcpClient
            {
                get { return tcpClient; }
            }

            public byte[] ReceiveBuffer
            {
                get { return receiveBuffer; }
            }

            public bool UseSsl
            {
                get { return useSsl; }
            }

            public bool Closed
            {
                get { return closed; }
            }

            public Stream Stream
            {
                get
                {
                    if (useSsl)
                    {
                        return sslStream;
                    }
                    else
                    {
                        return tcpClient.GetStream();
                    }
                }
            }
        }
    }
}

