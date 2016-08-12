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

namespace DTLS
{
	
   //struct {
   //  ProtocolVersion server_version;
   //  opaque cookie<0..2^8-1>; } HelloVerifyRequest;
	internal class HelloVerifyRequest : IHandshakeMessage
	{
		Version _ServerVersion;
		byte[] _Cookie;

		public THandshakeType MessageType { get { return THandshakeType.HelloVerifyRequest;} }


		public Version ServerVersion
		{
			get { return _ServerVersion; }
			set { _ServerVersion = value; }
		}

		public byte[] Cookie
		{
			get { return _Cookie; }
			set { _Cookie = value; }
		}

		public HelloVerifyRequest()
		{
			_ServerVersion = ServerHello.DefaultVersion;
		}

		public int CalculateSize(Version version)
		{
			int  result = 3; //Version + Length of cookie
			if (_Cookie != null)
				result += _Cookie.Length;
			return result;
		}

		public static HelloVerifyRequest Deserialise(Stream stream)
		{
			HelloVerifyRequest result = new HelloVerifyRequest();
			result._ServerVersion = new Version(255 - stream.ReadByte(), 255 - stream.ReadByte());
			int length = stream.ReadByte();
			if (length > 0)
			{
				result._Cookie = new byte[length];
				stream.Read(result._Cookie, 0, length);
			}
			return result;
		}

		public void Serialise(System.IO.Stream stream, Version version)
		{
			stream.WriteByte((byte)(255 - _ServerVersion.Major));
			stream.WriteByte((byte)(255 - _ServerVersion.Minor));
			stream.WriteByte((byte)_Cookie.Length);
			stream.Write(_Cookie, 0, _Cookie.Length);
		}
	}
}
