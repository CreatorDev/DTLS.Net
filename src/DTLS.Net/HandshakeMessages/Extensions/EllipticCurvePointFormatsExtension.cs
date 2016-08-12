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
	//rfc4492 section 5.1.2
	//    enum { uncompressed (0), ansiX962_compressed_prime (1),
	//       ansiX962_compressed_char2 (2), reserved (248..255)
	//} ECPointFormat;

	//struct {
	//    ECPointFormat ec_point_format_list<1..2^8-1>
	//} ECPointFormatList;
	internal class EllipticCurvePointFormatsExtension: IExtension
	{
		List<TEllipticCurvePointFormat> _SupportedPointFormats;


		public TExtensionType ExtensionType { get { return TExtensionType.EllipticCurvePointFormats;} }

		public List<TEllipticCurvePointFormat> SupportedPointFormats { get { return _SupportedPointFormats; } }

		public EllipticCurvePointFormatsExtension()
		{
			_SupportedPointFormats = new List<TEllipticCurvePointFormat>();
		}
		
		public int CalculateSize()
		{
			int result = 1;
			if (_SupportedPointFormats != null)
				result += _SupportedPointFormats.Count;
			return result;
		}

		public static EllipticCurvePointFormatsExtension Deserialise(Stream stream)
		{
			EllipticCurvePointFormatsExtension result = new EllipticCurvePointFormatsExtension();
			int length = stream.ReadByte();
			if (length > 0)
			{
				for (uint index = 0; index < length; index++)
				{
					result.SupportedPointFormats.Add((TEllipticCurvePointFormat)stream.ReadByte());
				}
			}
			return result;
		}

		public void Serialise(Stream stream)
		{
            stream.WriteByte((byte)_SupportedPointFormats.Count);
            foreach (TEllipticCurvePointFormat item in _SupportedPointFormats)
            {
                stream.WriteByte((byte)item);
            }
		}

	}	
}
