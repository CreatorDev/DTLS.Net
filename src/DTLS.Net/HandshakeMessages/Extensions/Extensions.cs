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
using System.IO;

namespace DTLS
{
    // Extension extensions<0..2^16-1>;


    //    struct {
    //    ExtensionType extension_type;
    //    opaque extension_data<0..2^16-1>;
    //} Extension;

    //enum {
    //    signature_algorithms(13), (65535)
    //} ExtensionType;


    internal class Extensions : List<Extension>
	{
		public int CalculateSize()
		{
			var result = 2;
			foreach (var item in this)
			{
				result += item.CalculateSize();
			}
			return result;
		}

		public static Extensions Deserialise(Stream stream, bool client)
		{
            if(stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

			Extensions result = null;
			if (stream.Position < stream.Length)
			{
				result = new Extensions();
				var length = NetworkByteOrderConverter.ToUInt16(stream);
				if (length > 0)
				{
					var extension = Extension.Deserialise(stream, client);
					while (extension != null)
					{
						result.Add(extension);
						extension = Extension.Deserialise(stream, client);
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

            uint length = 0;
            foreach (var item in this)
            {
                length += (uint)item.CalculateSize();
            }
            NetworkByteOrderConverter.WriteUInt16(stream, (ushort)length);
            foreach (var item in this)
            {
                item.Serialise(stream);
            }
		}
	}
}
