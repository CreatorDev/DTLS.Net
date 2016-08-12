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
using System.Collections.Generic;
using System.Linq;
using System.Text;
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
		private uint _UnixTime;
		private byte[] _RandomBytes = new byte[28];

		public uint UnixTime
		{
			get { return _UnixTime; }
			set { _UnixTime = value; }
		}

		public byte[] RandomBytes
		{
			get { return _RandomBytes; }
			set { _RandomBytes = value; }
		}


		public static RandomData Deserialise(Stream stream)
		{
			RandomData result = new RandomData();
			result._UnixTime = NetworkByteOrderConverter.ToUInt32(stream);
			stream.Read(result._RandomBytes, 0, 28);
			return result;
		}

		public void Generate()
		{
            TimeSpan unixTime = DateTime.UtcNow.Subtract(TLSUtils.UnixEpoch);
			_UnixTime = (uint)unixTime.TotalSeconds;
			RNGCryptoServiceProvider random = new RNGCryptoServiceProvider();
			random.GetBytes(_RandomBytes);
		}

		public byte[] Serialise()
		{
			byte[] result = new byte[32];
			NetworkByteOrderConverter.WriteUInt32(result,0, _UnixTime);
			Array.Copy(_RandomBytes, 0, result, 4, 28);
			return result;
		}

		public void Serialise(System.IO.Stream stream)
		{
			NetworkByteOrderConverter.WriteUInt32(stream, _UnixTime);
			stream.Write(_RandomBytes, 0, 28);
		}

	}
}
