using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;

using Xunit;

namespace System.Net.Security.Tests
{ 
    public class ParameterValidationTest
    {
        private DummyTcpServer remoteServer;

        public ParameterValidationTest()
        {
            remoteServer = new DummyTcpServer(
                new IPEndPoint(IPAddress.Loopback, 600), EncryptionPolicy.RequireEncryption);
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
        public void SslStreamConstructor_BadEncryptionPolicy_ThrowException()
        {
            using (var client = new TcpClient())
            { 
                client.Connect(remoteServer.RemoteEndPoint);

                Assert.Throws<ArgumentException>( () => {
                    SslStream sslStream = new SslStream(client.GetStream(), false, AllowAnyServerCertificate, null, (EncryptionPolicy)100);
                });
            }
        }
    }
}

