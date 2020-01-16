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
using System;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace TestClient
{
    public class Program
    {
        static byte[] HexToBytes(string hex)
        {
            var result = new byte[hex.Length / 2];
            var count = 0;
            for (var index = 0; index < hex.Length; index += 2)
            {
                result[count] = Convert.ToByte(hex.Substring(index, 2), 16);
                count++;
            }
            return result;
        }

        public static async Task Main(string[] args)
        {
            var exit = false;
            Console.WriteLine("Press any key to Connect to Server");
            Console.ReadKey(true);
            var client = new Client(new IPEndPoint(IPAddress.Any, 56239));
            client.PSKIdentities.AddIdentity(Encoding.UTF8.GetBytes("oFIrQFrW8EWcZ5u7eGfrkw"), HexToBytes("7CCDE14A5CF3B71C0C08C8B7F9E5"));
            client.LoadCertificateFromPem(@"Client.pem");
            client.SupportedCipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8);
            client.ConnectToServerWithTimeoutAsync(new IPEndPoint(IPAddress.Parse("127.0.0.1"), 5684));
            Console.CancelKeyPress += delegate (object sender, ConsoleCancelEventArgs e)
            {
                e.Cancel = true;
                exit = true;
            };
            Console.WriteLine();
            Console.WriteLine("Press Ctrl+C to stop the client. Any other characters are send to server");
            Console.WriteLine();
            while (!exit)
            {
                if (Console.KeyAvailable)
                {
                    var pressedKey = Console.ReadKey(true);
                    await client.SendAsync(Encoding.UTF8.GetBytes(pressedKey.KeyChar.ToString()));
                }
            }
            await client.StopAsync();
        }
    }
}
