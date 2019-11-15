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
    //    struct {
    //        select(ClientOrServerExtension) {
    //            case client:
    //              CertificateType client_certificate_types<1..2^8-1>;
    //            case server:
    //              CertificateType client_certificate_type;
    //        }
    //} ClientCertTypeExtension;
    internal class ClientCertificateTypeExtension : IExtension
	{
        public TExtensionType ExtensionType => TExtensionType.ClientCertificateType;

        public byte[] CertificateTypes { get; set; }

        public ClientCertificateTypeExtension() { }

		public ClientCertificateTypeExtension(TCertificateType certificateType)
		{
            this.CertificateTypes = new byte[1];
            this.CertificateTypes[0] = (byte)certificateType;
		}

		public int CalculateSize()
		{
			var result = 1;
			if (this.CertificateTypes != null)
            {
                result += this.CertificateTypes.Length;
            }

            return result;
		}

		public static ClientCertificateTypeExtension Deserialise(Stream stream, bool client)
		{
            if(stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

			var result = new ClientCertificateTypeExtension();
			var length = NetworkByteOrderConverter.ToUInt16(stream);
			if (length > 0)
			{
				result.CertificateTypes = new byte[length];
				stream.Read(result.CertificateTypes, 0, length);
			}

			return result;
		}

        public void Serialise(Stream stream) => throw new NotImplementedException();
    }

}
