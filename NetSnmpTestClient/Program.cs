/***********************************************************************************************************************
 Copyright (c) 2016, Imagination Technologies Limited and/or its affiliated group companies.
 All rights reserved.

 Redistribution and use in source and binary forms, with or without modification, are permitted provided that the
 following conditions are met:
     1. Redistributions of source code must retain the above copyright notice, this list of conditions and the
        following disclaimer.
     2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the
        following disclaimer in the documentation and/or other materials provided with the distribution.
     3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote
        products derived from this software without specific prior written permission.

 THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
 INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE 
 DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, 
 SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, 
 WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE 
 USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
***********************************************************************************************************************/

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
