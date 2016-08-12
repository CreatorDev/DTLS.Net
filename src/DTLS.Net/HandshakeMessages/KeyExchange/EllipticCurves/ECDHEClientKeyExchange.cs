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
using Org.BouncyCastle.Crypto.Parameters;

namespace DTLS
{
	internal class ECDHEClientKeyExchange : IHandshakeMessage
	{

		private byte[] _PublicKeyBytes;
		
		public THandshakeType MessageType
		{
			get { return THandshakeType.ClientKeyExchange; }
		}

		public byte[] PublicKeyBytes
		{
			get { return _PublicKeyBytes; }
		}


		public int CalculateSize(Version version)
		{
            int result = 1;
            if (_PublicKeyBytes != null)
            {
                result += _PublicKeyBytes.Length;
            }
            return result;
		}

        public ECDHEClientKeyExchange()
        {

        }

        public ECDHEClientKeyExchange(ECPublicKeyParameters publicKey)
        {
            _PublicKeyBytes = publicKey.Q.GetEncoded();
        }

		public void Serialise(System.IO.Stream stream, Version version)
		{
            if (_PublicKeyBytes == null)
            {
                stream.WriteByte(0);
            }
            else
            {
                stream.WriteByte((byte)_PublicKeyBytes.Length);
                stream.Write(_PublicKeyBytes, 0, _PublicKeyBytes.Length);
            }
		}

		public static ECDHEClientKeyExchange Deserialise(System.IO.Stream stream)
		{
			ECDHEClientKeyExchange result = null;
			int length = stream.ReadByte();
			if (length > 0)
			{
				result = new ECDHEClientKeyExchange();
				result._PublicKeyBytes = new byte[length];
				stream.Read(result._PublicKeyBytes, 0, length);
			}
			return result;			
		}
	}
}
