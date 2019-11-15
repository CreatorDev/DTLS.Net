using DTLS;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace NetSnmpTestClient
{
    public class Program
    {
        public static void Main()
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            var myCertCollection = store.Certificates.Find(X509FindType.FindByThumbprint, "608cb982f5ec33f285b2346b67db6cf306bf9399", true);

            var chain = new X509Chain();
            chain.Build(myCertCollection[0]);

            var client = new Client(new IPEndPoint(IPAddress.Any, 0));
            //var client = new Client(new IPEndPoint(IPAddress.IPv6Any, 0));
            client.LoadX509Certificate(chain);
            client.SupportedCipherSuites.Add(TCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            //client.ConnectToServer(new IPEndPoint(IPAddress.Parse("2620:131:101E:441:B8AD:DEAC:3150:202C"), 10161));
            client.ConnectToServer(new IPEndPoint(IPAddress.Parse("192.168.0.23"), 10167));
            client.Send(Encoding.UTF8.GetBytes("TEST"));
            store.Close();
        }
    }
}
