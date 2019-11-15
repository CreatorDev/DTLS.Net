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
        public THandshakeType MessageType => THandshakeType.ClientKeyExchange;

        public byte[] PSKIdentity { get; set; }

        public int CalculateSize(Version version)
		{
            var result = 2;
            if (this.PSKIdentity != null)
            {
                result += this.PSKIdentity.Length;
            }

            return result;
		}

		public void Serialise(Stream stream, Version version)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (this.PSKIdentity == null)
            {
                NetworkByteOrderConverter.WriteUInt16(stream, 0);
            }
            else
            {
                NetworkByteOrderConverter.WriteUInt16(stream, (ushort)this.PSKIdentity.Length);
                stream.Write(this.PSKIdentity, 0, this.PSKIdentity.Length);
            }
		}

        public static PSKClientKeyExchange Deserialise(Stream stream)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            PSKClientKeyExchange result = null;
            var pskIdentityLength = NetworkByteOrderConverter.ToUInt16(stream);
            if (pskIdentityLength > 0)
            {
                result = new PSKClientKeyExchange
                {
                    PSKIdentity = new byte[pskIdentityLength]
                };
                stream.Read(result.PSKIdentity, 0, pskIdentityLength);
            }
			return result;
		}
	}
}