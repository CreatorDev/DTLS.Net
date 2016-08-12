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
	//    struct {
	//    ExtensionType extension_type;
	//    opaque extension_data<0..2^16-1>;
	//} Extension;

	internal class Extension
	{
		TExtensionType _ExtensionType;
		IExtension _SpecifcExtension;
		byte[] _Data;

		public TExtensionType ExtensionType
		{
			get { return _ExtensionType; }
			set { _ExtensionType = value; }
		}

		public byte[] Data
		{
			get { return _Data; }
			set { _Data = value; }
		}

		public IExtension SpecifcExtension
		{
			get { return _SpecifcExtension; }
			set { _SpecifcExtension = value; }
		}

		public int CalculateSize()
		{
			int result = 4;
			if (_SpecifcExtension != null)
			{
				result += _SpecifcExtension.CalculateSize();
			}
			return result;
		}

        public Extension()
        {

        }

        public Extension(IExtension specifcExtension)
        {
            _ExtensionType = specifcExtension.ExtensionType;
            _SpecifcExtension = specifcExtension;
        }


		public static Extension Deserialise(Stream stream, bool client)
		{
			Extension result = null;
			if (stream.Position < stream.Length)
			{
				result = new Extension();
				result._ExtensionType = (TExtensionType)NetworkByteOrderConverter.ToUInt16(stream);
				ushort length = NetworkByteOrderConverter.ToUInt16(stream);
				if (length > 0)
				{
					if (result._ExtensionType == TExtensionType.EllipticCurves)
					{
						result._SpecifcExtension = EllipticCurvesExtension.Deserialise(stream);
					}
					else if (result._ExtensionType == TExtensionType.ClientCertificateType)
					{
						result._SpecifcExtension = ClientCertificateTypeExtension.Deserialise(stream, client);
					}
					else if (result._ExtensionType == TExtensionType.ServerCertificateType)
					{
						result._SpecifcExtension = ServerCertificateTypeExtension.Deserialise(stream, client);
					}	
					else if (result._ExtensionType == TExtensionType.SignatureAlgorithms)
					{
						result._SpecifcExtension = SignatureAlgorithmsExtension.Deserialise(stream);
					}							
					else
					{
						result._Data = new byte[length];
						stream.Read(result._Data, 0, length);
					}
				}
			}
			return result;
		}

		public void Serialise(System.IO.Stream stream)
		{
			NetworkByteOrderConverter.WriteUInt16(stream, (ushort)_ExtensionType);
			int length = 0;
			if (_SpecifcExtension != null)
			{
				length += _SpecifcExtension.CalculateSize();
			}
			NetworkByteOrderConverter.WriteUInt16(stream, (ushort)length);
			if (_SpecifcExtension != null)
			{
				_SpecifcExtension.Serialise(stream);
			}
		}
	}
}
