using System.IO;
using System.Net.Sockets;
using System.Net.Test.Common;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

using Xunit;
using Xunit.Abstractions;

namespace System.Net.Security.Tests
{
    public class ClientDefaultEncryptionTest
    {
        private readonly ITestOutputHelper _log;

        private DummyTcpServer serverRequireEncryption;
        private DummyTcpServer serverAllowNoEncryption;
        private DummyTcpServer serverNoEncryption;

        public ClientDefaultEncryptionTest()
        {
            _log = TestLogging.GetInstance();

            serverRequireEncryption = new DummyTcpServer(
                new IPEndPoint(IPAddress.Loopback, 400), EncryptionPolicy.RequireEncryption);
            serverAllowNoEncryption = new DummyTcpServer(
                new IPEndPoint(IPAddress.Loopback, 401), EncryptionPolicy.AllowNoEncryption);
            serverNoEncryption = new DummyTcpServer(
                new IPEndPoint(IPAddress.Loopback, 402), EncryptionPolicy.NoEncryption);
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
        public void ClientDefaultEncryption_ServerRequireEncryption_ConnectWithEncryption()
        {
            SslStream sslStream;
            TcpClient client;

            client = new TcpClient();
            client.Connect(serverRequireEncryption.RemoteEndPoint);

            sslStream = new SslStream(client.GetStream(), false, AllowAnyServerCertificate, null);
            sslStream.AuthenticateAsClient("localhost", null, TestConfiguration.DefaultSslProtocols, false);
            _log.WriteLine("Client({0}) authenticated to server({1}) with encryption cipher: {2} {3}-bit strength",
                client.Client.LocalEndPoint, client.Client.RemoteEndPoint,
                sslStream.CipherAlgorithm, sslStream.CipherStrength);
            Assert.True(sslStream.CipherAlgorithm != CipherAlgorithmType.Null, "Cipher algorithm should not be NULL");
            Assert.True(sslStream.CipherStrength > 0, "Cipher strength should be greater than 0");
            sslStream.Dispose();
            client.Dispose();
        }

        [Fact]
        public void ClientDefaultEncryption_ServerAllowNoEncryption_ConnectWithEncryption()
        {
            SslStream sslStream;
            TcpClient client;

            client = new TcpClient();
            client.Connect(serverAllowNoEncryption.RemoteEndPoint);

            sslStream = new SslStream(client.GetStream(), false, AllowAnyServerCertificate, null);
            sslStream.AuthenticateAsClient("localhost", null, TestConfiguration.DefaultSslProtocols, false);
            _log.WriteLine("Client({0}) authenticated to server({1}) with encryption cipher: {2} {3}-bit strength",
                client.Client.LocalEndPoint, client.Client.RemoteEndPoint,
                sslStream.CipherAlgorithm, sslStream.CipherStrength);
            Assert.True(sslStream.CipherAlgorithm != CipherAlgorithmType.Null, "Cipher algorithm should not be NULL");
            Assert.True(sslStream.CipherStrength > 0, "Cipher strength should be greater than 0");
            sslStream.Dispose();
            client.Dispose();
        }

        [Fact]
        public void ClientDefaultEncryption_ServerNoEncryption_NoConnect()
        {
            using (var client = new TcpClient())
            {
                client.Connect(serverNoEncryption.RemoteEndPoint);

                using (var sslStream = new SslStream(client.GetStream(), false, AllowAnyServerCertificate, null))
                {
                        Assert.Throws<IOException>(() => {
                            sslStream.AuthenticateAsClient("localhost", null, TestConfiguration.DefaultSslProtocols, false);
                        });
                }
            }
        }
    }
}

