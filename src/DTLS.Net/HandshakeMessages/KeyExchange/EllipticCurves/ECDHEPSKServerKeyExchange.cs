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
      //        case ec_diffie_hellman_psk:  /* NEW */
      //            opaque psk_identity_hint<0..2^16-1>;
      //            ServerECDHParams params;
      //    };
      //} ServerKeyExchange;
    internal class ECDHEPSKServerKeyExchange : IHandshakeMessage
	{
        private byte[] _PSKIdentityHint;
        private byte[] _ServerParams;

        private TEllipticCurveType _EllipticCurveType;
        private TEllipticCurve _EllipticCurve;
        private byte[] _PublicKeyBytes;

        public THandshakeType MessageType
        {
            get { return THandshakeType.ServerKeyExchange; }
        }

        public byte[] PSKIdentityHint
        {
            get { return _PSKIdentityHint; }
            set { _PSKIdentityHint = value; }
        }

        public TEllipticCurve EllipticCurve
        {
            get { return _EllipticCurve; }
        }

        public byte[] PublicKeyBytes
        {
            get { return _PublicKeyBytes; }
        }

        public ECDHEPSKServerKeyExchange()
        {
            _EllipticCurveType = TEllipticCurveType.NamedCurve;
        }

        public ECDHEPSKServerKeyExchange(ECDHEKeyExchange keyExchange)
        {
            _EllipticCurveType = TEllipticCurveType.NamedCurve;
            _EllipticCurve = keyExchange.Curve;
            System.IO.MemoryStream stream = new System.IO.MemoryStream();
            stream.WriteByte((byte)_EllipticCurveType);
            NetworkByteOrderConverter.WriteUInt16(stream, (ushort)_EllipticCurve);
            byte[] pointEncoded = keyExchange.PublicKey.Q.GetEncoded(false);
            stream.WriteByte((byte)pointEncoded.Length);
            stream.Write(pointEncoded, 0, pointEncoded.Length);
            _ServerParams = stream.ToArray();
        }

        public int CalculateSize(Version version)
        {
            int result = 2;
            if (_PSKIdentityHint != null)
            {
                result += _PSKIdentityHint.Length;
            }
            if (_ServerParams != null)
            {
                result += _ServerParams.Length;
            }
            return result;
        }

        public static ECDHEPSKServerKeyExchange Deserialise(System.IO.Stream stream, Version version)
        {
            ECDHEPSKServerKeyExchange result = new ECDHEPSKServerKeyExchange();

            int pdkIdentityHintLenth = NetworkByteOrderConverter.ToUInt16(stream);
            if (pdkIdentityHintLenth > 0)
            {
                result._PSKIdentityHint = new byte[pdkIdentityHintLenth];
                stream.Read(result._PSKIdentityHint, 0, pdkIdentityHintLenth);
            }
            result._EllipticCurveType = (TEllipticCurveType)stream.ReadByte();
            result._EllipticCurve = (TEllipticCurve)NetworkByteOrderConverter.ToUInt16(stream);
            int length = stream.ReadByte();
            if (length > 0)
            {
                result._PublicKeyBytes = new byte[length];
                stream.Read(result._PublicKeyBytes, 0, length);
            }
            return result;
        }


        public void Serialise(System.IO.Stream stream, Version version)
        {
            if (_PSKIdentityHint != null)
            {
                NetworkByteOrderConverter.WriteUInt16(stream, (ushort)_PSKIdentityHint.Length);
                stream.Write(_PSKIdentityHint, 0, _PSKIdentityHint.Length);
            }
            else
                NetworkByteOrderConverter.WriteUInt16(stream, 0);
            if (_ServerParams != null)
            {
                stream.Write(_ServerParams, 0, _ServerParams.Length);
            }
        }

	}
}
