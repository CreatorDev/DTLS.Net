using DTLS;
using System;
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
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                var myCertCollection = store.Certificates.Find(X509FindType.FindByThumbprint, "", true);
                using (var chain = new X509Chain())
                {
                    chain.Build(myCertCollection[0]);

                    //If reaching out to an IPv6 address you will need to create a client with an IPv6 endpoint
                    //var client = new Client(new IPEndPoint(IPAddress.IPv6Any, 0));
                    using (var client = new Client(new IPEndPoint(IPAddress.Any, 0)))
                    {
                        client.LoadX509Certificate(chain);
                        client.SupportedCipherSuites.Add(TCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
                        await client.ConnectToServerAsync(new IPEndPoint(IPAddress.Parse(""), 10161), TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(2));
                        await client.SendAsync(Encoding.UTF8.GetBytes("TEST"), TimeSpan.FromSeconds(5));
                    }
                }
            }
        }
    }
}
