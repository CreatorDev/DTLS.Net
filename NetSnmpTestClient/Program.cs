using DTLS;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace NetSnmpTestClient
{
    public class Program
    {
        public static async Task Main()
        {
            var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
            store.Open(OpenFlags.ReadOnly);
            var myCertCollection = store.Certificates.Find(X509FindType.FindByThumbprint, "", true);

            var chain = new X509Chain();
            chain.Build(myCertCollection[0]);

            var client = new Client(new IPEndPoint(IPAddress.Any, 0));
            //var client = new Client(new IPEndPoint(IPAddress.IPv6Any, 0));
            client.LoadX509Certificate(chain);
            client.SupportedCipherSuites.Add(TCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            //client.ConnectToServer(new IPEndPoint(IPAddress.Parse("2620:131:101e:441:9a1d:faff:feb1:3521"), 10161), 2000);
            await client.ConnectToServerWithTimeoutAsync(new IPEndPoint(IPAddress.Parse("10.247.160.3"), 10161), 5000);
            await client.SendWithTimeoutAsync(Encoding.UTF8.GetBytes("TEST"), 5000);
            store.Close();
        }
    }
}
