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

namespace DTLS
{
      //struct {
      //    select (KeyExchangeAlgorithm) {
      //        /* other cases for rsa, diffie_hellman, etc. */
      //        case psk:   /* NEW */
      //            opaque psk_identity<0..2^16-1>;
      //    } exchange_keys;
      //} ClientKeyExchange;
	internal class PSKClientKeyExchange : IHandshakeMessage
	{
        private byte[] _PSKIdentity;
		
		public THandshakeType MessageType
		{
			get { return THandshakeType.ClientKeyExchange; }
		}

        public byte[] PSKIdentity
        {
            get { return _PSKIdentity; }
            set { _PSKIdentity = value; }
        }


		public int CalculateSize(Version version)
		{
            int result = 2;
            if (_PSKIdentity != null)
                result += _PSKIdentity.Length;
            return result;
		}

		public void Serialise(System.IO.Stream stream, Version version)
		{
            if (_PSKIdentity == null)
                NetworkByteOrderConverter.WriteUInt16(stream, 0);
            else
            {
                NetworkByteOrderConverter.WriteUInt16(stream, (ushort)_PSKIdentity.Length);
                stream.Write(_PSKIdentity, 0, _PSKIdentity.Length);
            }
		}

        public static PSKClientKeyExchange Deserialise(System.IO.Stream stream)
		{
            PSKClientKeyExchange result = null;
            ushort pskIdentityLength = NetworkByteOrderConverter.ToUInt16(stream);
            if (pskIdentityLength > 0)
            {
                result = new PSKClientKeyExchange();
                result._PSKIdentity = new byte[pskIdentityLength];
                stream.Read(result._PSKIdentity, 0, pskIdentityLength);
            }
			return result;			
		}
	}
}
