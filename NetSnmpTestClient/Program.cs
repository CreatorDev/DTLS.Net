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
            var myCertCollection = store.Certificates.Find(X509FindType.FindByThumbprint, "629b2ad8d378b816e6d04f614f5f3b164bb8ede8", true);

            var chain = new X509Chain();
            chain.Build(myCertCollection[0]);

            var client = new Client(new IPEndPoint(IPAddress.Any, 0));
            //var client = new Client(new IPEndPoint(IPAddress.IPv6Any, 0));
            client.LoadX509Certificate(chain);
            client.SupportedCipherSuites.Add(TCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            //client.ConnectToServer(new IPEndPoint(IPAddress.Parse("2620:131:101E:441:B8AD:DEAC:3150:202C"), 10161));
            client.ConnectToServer(new IPEndPoint(IPAddress.Parse("10.247.160.3"), 10161), 1000);
            await client.SendAsync(Encoding.UTF8.GetBytes("TEST"));
            store.Close();
        }
    }
}
