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
    //rfc4492 section 5.1.2
    //enum {
    //    sect163k1 (1), sect163r1 (2), sect163r2 (3),
    //    sect193r1 (4), sect193r2 (5), sect233k1 (6),
    //    sect233r1 (7), sect239k1 (8), sect283k1 (9),
    //    sect283r1 (10), sect409k1 (11), sect409r1 (12),
    //    sect571k1 (13), sect571r1 (14), secp160k1 (15),
    //    secp160r1 (16), secp160r2 (17), secp192k1 (18),
    //    secp192r1 (19), secp224k1 (20), secp224r1 (21),
    //    secp256k1 (22), secp256r1 (23), secp384r1 (24),
    //    secp521r1 (25),
    //    reserved (0xFE00..0xFEFF),
    //    arbitrary_explicit_prime_curves(0xFF01),
    //    arbitrary_explicit_char2_curves(0xFF02),
    //    (0xFFFF)
    //} NamedCurve;

    //struct {
    //    NamedCurve elliptic_curve_list<1..2^16-1>
    //} EllipticCurveList;

    internal class EllipticCurvesExtension : IExtension
	{
        public TExtensionType ExtensionType => TExtensionType.EllipticCurves;

        public List<TEllipticCurve> SupportedCurves { get; }

        public EllipticCurvesExtension() => this.SupportedCurves = new List<TEllipticCurve>();


        public int CalculateSize()
		{
			var result = 2;
			if (this.SupportedCurves != null)
            {
                result += (this.SupportedCurves.Count * 2);
            }

            return result;
		}


		public static EllipticCurvesExtension Deserialise(Stream stream)
		{
            if(stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

			var result = new EllipticCurvesExtension();
			var length = NetworkByteOrderConverter.ToUInt16(stream);
			var supportedCurvesLength = (ushort)(length / 2);
			if (supportedCurvesLength > 0)
			{
				for (uint index = 0; index < supportedCurvesLength; index++)
				{
					result.SupportedCurves.Add((TEllipticCurve)NetworkByteOrderConverter.ToUInt16(stream));
				}
			}

			return result;
		}

		public void Serialise(Stream stream)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            ushort length = 0;
            if (this.SupportedCurves == null)
            {
                NetworkByteOrderConverter.WriteUInt16(stream, length);
            }
            else
            {
                length = (ushort)(this.SupportedCurves.Count * 2);
                NetworkByteOrderConverter.WriteUInt16(stream, length);
                for (var index = 0; index < this.SupportedCurves.Count; index++)
                {
                    NetworkByteOrderConverter.WriteUInt16(stream, (ushort)this.SupportedCurves[index]);
                }
            }
        }
	}
}
