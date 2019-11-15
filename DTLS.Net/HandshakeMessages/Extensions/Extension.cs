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
    //    ExtensionType extension_type;
    //    opaque extension_data<0..2^16-1>;
    //} Extension;

    internal class Extension
	{
        public TExtensionType ExtensionType { get; set; }

        public byte[] Data { get; set; }

        public IExtension SpecificExtension { get; set; }

        public int CalculateSize()
		{
			var result = 4;
			if (this.SpecificExtension != null)
			{
				result += this.SpecificExtension.CalculateSize();
			}
			return result;
		}

        public Extension() { }

        public Extension(IExtension specificExtension)
        {
            this.ExtensionType = specificExtension.ExtensionType;
            this.SpecificExtension = specificExtension;
        }

		public static Extension Deserialise(Stream stream, bool client)
		{
            if(stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

			Extension result = null;
			if (stream.Position < stream.Length)
			{
                result = new Extension
                {
                    ExtensionType = (TExtensionType)NetworkByteOrderConverter.ToUInt16(stream)
                };

                var length = NetworkByteOrderConverter.ToUInt16(stream);
				if (length > 0)
				{
					if (result.ExtensionType == TExtensionType.EllipticCurves)
					{
						result.SpecificExtension = EllipticCurvesExtension.Deserialise(stream);
					}
					else if (result.ExtensionType == TExtensionType.ClientCertificateType)
					{
						result.SpecificExtension = ClientCertificateTypeExtension.Deserialise(stream, client);
					}
					else if (result.ExtensionType == TExtensionType.ServerCertificateType)
					{
						result.SpecificExtension = ServerCertificateTypeExtension.Deserialise(stream, client);
					}	
					else if (result.ExtensionType == TExtensionType.SignatureAlgorithms)
					{
						result.SpecificExtension = SignatureAlgorithmsExtension.Deserialise(stream);
					}
					else
					{
						result.Data = new byte[length];
						stream.Read(result.Data, 0, length);
					}
				}
			}
			return result;
		}

		public void Serialise(Stream stream)
		{
            if(stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

			NetworkByteOrderConverter.WriteUInt16(stream, (ushort)this.ExtensionType);
			var length = 0;
			if (this.SpecificExtension != null)
			{
				length += this.SpecificExtension.CalculateSize();
			}
			NetworkByteOrderConverter.WriteUInt16(stream, (ushort)length);
			if (this.SpecificExtension != null)
			{
                this.SpecificExtension.Serialise(stream);
			}
		}
	}
}
