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
using System.Numerics;

namespace DTLS
{
	// either y² = x³ + ax + b  (mod p)
	// or  y² + xy = x³ + ax² + b

	internal class EllipticCurve
	{
		private BigInteger _A;
		private BigInteger _B;
		private BigInteger _Order;
		private BigInteger _Cofactor;

		private EllipticCurvePoint _BasePoint;

		public BigInteger A
		{
			get { return _A; }
		}

		public BigInteger B
		{
			get { return _B; }
		}

		public BigInteger Order
		{
			get { return _Order; }
		}

		public BigInteger Cofactor
		{
			get { return _Cofactor; }
		}

		public EllipticCurvePoint BasePoint
		{
			get { return _BasePoint; }
		}

		public EllipticCurve(BigInteger a, BigInteger b, BigInteger order, BigInteger cofactor, EllipticCurvePoint basePoint)
		{
			_A = a;
			_B = b;
			_Order = order;
			_Cofactor = cofactor;
			_BasePoint = basePoint;
		}

	}
}
