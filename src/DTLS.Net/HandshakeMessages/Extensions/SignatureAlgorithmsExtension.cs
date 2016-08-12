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
	  //    enum {
	  //    none(0), md5(1), sha1(2), sha224(3), sha256(4), sha384(5),
	  //    sha512(6), (255)
	  //} HashAlgorithm;

	  //enum { anonymous(0), rsa(1), dsa(2), ecdsa(3), (255) }
	  //  SignatureAlgorithm;

	  //struct {
	  //      HashAlgorithm hash;
	  //      SignatureAlgorithm signature;
	  //} SignatureAndHashAlgorithm;

	  //SignatureAndHashAlgorithm
	  //  supported_signature_algorithms<2..2^16-2>;


	internal class SignatureAlgorithmsExtension : IExtension
	{
		public TExtensionType ExtensionType { get { return TExtensionType.SignatureAlgorithms; } }


		public List<SignatureHashAlgorithm> SupportedAlgorithms { get; private set; }

		public SignatureAlgorithmsExtension()
		{
			SupportedAlgorithms = new List<SignatureHashAlgorithm>();
		}

		public int CalculateSize()
		{
			int result = 2;
			if (SupportedAlgorithms != null)
				result += (SupportedAlgorithms.Count * 2);
			return result;
		}


		public static SignatureAlgorithmsExtension Deserialise(Stream stream)
		{
			SignatureAlgorithmsExtension result = new SignatureAlgorithmsExtension();
			ushort length = NetworkByteOrderConverter.ToUInt16(stream);
			ushort supportedAlgorithmsLength = (ushort)(length / 2);
			if (supportedAlgorithmsLength > 0)
			{
				for (uint index = 0; index < supportedAlgorithmsLength; index++)
				{
					THashAlgorithm hash = (THashAlgorithm)stream.ReadByte();
					TSignatureAlgorithm signature = (TSignatureAlgorithm)stream.ReadByte();
					result.SupportedAlgorithms.Add(new SignatureHashAlgorithm() { Hash = hash, Signature = signature });
				}
			}
			return result;
		}

		public void Serialise(Stream stream)
		{
            ushort length = 0;
            if (SupportedAlgorithms == null)
                NetworkByteOrderConverter.WriteUInt16(stream, length);
            else
            {
                length = (ushort)(SupportedAlgorithms.Count * 2);
                NetworkByteOrderConverter.WriteUInt16(stream, length);
                for (int index = 0; index < SupportedAlgorithms.Count; index++)
                {
                    stream.WriteByte((byte)SupportedAlgorithms[index].Hash);
                    stream.WriteByte((byte)SupportedAlgorithms[index].Signature);
                }
            }
        }

	}
}
