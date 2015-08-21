using System.Net.Sockets;
using System.Net.Test.Common;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Xunit;
using Xunit.Abstractions;

namespace System.Net.Security.Tests
{
    public class ServerAllowNoEncryptionTest
    {
        private readonly ITestOutputHelper _log;
        private DummyTcpServer serverAllowNoEncryption;

        public ServerAllowNoEncryptionTest()
        {
            _log = TestLogging.GetInstance();

            serverAllowNoEncryption = new DummyTcpServer(
                new IPEndPoint(IPAddress.Loopback, 401), EncryptionPolicy.AllowNoEncryption);
        }

        // The following method is invoked by the RemoteCertificateValidationDelegate.
        public bool AllowAnyServerCertificate(
              object sender,
              X509Certificate certificate,
              X509Chain chain,
              SslPolicyErrors sslPolicyErrors)
        {
            return true;  // allow everything
        }

        [Fact]
        public void ServerAllowNoEncryption_ClientRequireEncryption_ConnectWithEncryption()
        {
            SslStream sslStream;
            TcpClient client;

            client = new TcpClient();
            client.Connect(serverAllowNoEncryption.RemoteEndPoint);

            sslStream = new SslStream(client.GetStream(), false, AllowAnyServerCertificate, null, EncryptionPolicy.RequireEncryption);
            sslStream.AuthenticateAsClient("localhost", null, TestConfiguration.DefaultSslProtocols, false);
            _log.WriteLine("Client({0}) authenticated to server({1}) with encryption cipher: {2} {3}-bit strength",
                client.Client.LocalEndPoint, client.Client.RemoteEndPoint, 
                sslStream.CipherAlgorithm, sslStream.CipherStrength);
            Assert.NotEqual(CipherAlgorithmType.Null, sslStream.CipherAlgorithm);
            Assert.True(sslStream.CipherStrength > 0);
            sslStream.Dispose();
            client.Dispose();
        }

        [Fact]
        public void ServerAllowNoEncryption_ClientAllowNoEncryption_ConnectWithEncryption()
        {
            SslStream sslStream;
            TcpClient client;

            client = new TcpClient();
            client.Connect(serverAllowNoEncryption.RemoteEndPoint);

            sslStream = new SslStream(client.GetStream(), false, AllowAnyServerCertificate, null, EncryptionPolicy.AllowNoEncryption);
            sslStream.AuthenticateAsClient("localhost", null, TestConfiguration.DefaultSslProtocols, false);
            _log.WriteLine("Client({0}) authenticated to server({1}) with encryption cipher: {2} {3}-bit strength",
                client.Client.LocalEndPoint, client.Client.RemoteEndPoint,
                sslStream.CipherAlgorithm, sslStream.CipherStrength);
            Assert.NotEqual(CipherAlgorithmType.Null, sslStream.CipherAlgorithm);
            Assert.True(sslStream.CipherStrength > 0, "Cipher strength should be greater than 0");
            sslStream.Dispose();
            client.Dispose();
        }

        [Fact]
        public void ServerAllowNoEncryption_ClientNoEncryption_ConnectWithNoEncryption()
        {
            using (var client = new TcpClient())
            {
                client.Connect(serverAllowNoEncryption.RemoteEndPoint);

                using (var sslStream = new SslStream(client.GetStream(), false, AllowAnyServerCertificate, null, EncryptionPolicy.NoEncryption))
                {
                    sslStream.AuthenticateAsClient("localhost", null, TestConfiguration.DefaultSslProtocols, false);
                    _log.WriteLine("Client({0}) authenticated to server({1}) with encryption cipher: {2} {3}-bit strength",
                        client.Client.LocalEndPoint, client.Client.RemoteEndPoint,
                        sslStream.CipherAlgorithm, sslStream.CipherStrength);

                    CipherAlgorithmType expected = CipherAlgorithmType.Null;
                    Assert.Equal(expected, sslStream.CipherAlgorithm);
                    Assert.Equal(0, sslStream.CipherStrength);
                }
            }
        }
    }
}

