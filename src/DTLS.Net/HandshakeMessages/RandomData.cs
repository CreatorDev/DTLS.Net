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

using System;
using System.IO;
using System.Security.Cryptography;

namespace DTLS
{
    //    struct {
    //    uint32 gmt_unix_time;
    //    opaque random_bytes[28];
    //} Random;

    internal class RandomData
	{
        public uint UnixTime { get; set; }

        public byte[] RandomBytes { get; set; } = new byte[28];

        public static RandomData Deserialise(Stream stream)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            var result = new RandomData
            {
                UnixTime = NetworkByteOrderConverter.ToUInt32(stream)
            };

            stream.Read(result.RandomBytes, 0, 28);
			return result;
		}

		public void Generate()
		{
            var unixTime = DateTime.UtcNow.Subtract(TLSUtils.UnixEpoch);
            this.UnixTime = (uint)unixTime.TotalSeconds;
			var random = new RNGCryptoServiceProvider();
			random.GetBytes(this.RandomBytes);
		}

		public byte[] Serialise()
		{
			var result = new byte[32];
			NetworkByteOrderConverter.WriteUInt32(result,0, this.UnixTime);
			Array.Copy(this.RandomBytes, 0, result, 4, 28);
			return result;
		}

		public void Serialise(Stream stream)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            NetworkByteOrderConverter.WriteUInt32(stream, this.UnixTime);
			stream.Write(this.RandomBytes, 0, 28);
		}
	}
}