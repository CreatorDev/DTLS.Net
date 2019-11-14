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

using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Signers;
using System;
using System.IO;

namespace DTLS
{
    //    struct {
    //    opaque a <1..2^8-1>;
    //    opaque b <1..2^8-1>;
    //} ECCurve;

    //enum { explicit_prime (1), explicit_char2 (2),
    //       named_curve (3), reserved(248..255) } ECCurveType;
    //    struct {
    //    opaque point <1..2^8-1>;
    //} ECPoint;
    //enum { ec_basis_trinomial, ec_basis_pentanomial } ECBasisType;
    //            struct {
    //            ECCurveType    curve_type;
    //            select (curve_type) {
    //                case explicit_prime:
    //                    opaque      prime_p <1..2^8-1>;
    //                    ECCurve     curve;
    //                    ECPoint     base;
    //                    opaque      order <1..2^8-1>;
    //                    opaque      cofactor <1..2^8-1>;
    //                case explicit_char2:
    //                    uint16      m;
    //                    ECBasisType basis;
    //                    select (basis) {
    //                        case ec_trinomial:
    //                            opaque  k <1..2^8-1>;
    //                        case ec_pentanomial:
    //                            opaque  k1 <1..2^8-1>;
    //                            opaque  k2 <1..2^8-1>;
    //                            opaque  k3 <1..2^8-1>;
    //                    };
    //                    ECCurve     curve;
    //                    ECPoint     base;
    //                    opaque      order <1..2^8-1>;
    //                    opaque      cofactor <1..2^8-1>;



    //Blake-Wilson, et al.         Informational                     [Page 18]

    //RFC 4492               ECC Cipher Suites for TLS                May 2006


    //                case named_curve:
    //                    NamedCurve namedcurve;
    //            };
    //        } ECParameters;

    //struct {
    //    ECParameters    curve_params;
    //    ECPoint         public;
    //} ServerECDHParams;


    //       enum { ec_diffie_hellman } KeyExchangeAlgorithm;

    //ec_diffie_hellman:   Indicates the ServerKeyExchange message contains
    //   an ECDH public key.

    //     select (KeyExchangeAlgorithm) {
    //         case ec_diffie_hellman:
    //             ServerECDHParams    params;
    //             Signature           signed_params;
    //     } ServerKeyExchange;



    //  enum { ecdsa } SignatureAlgorithm;

    //  select (SignatureAlgorithm) {
    //      case ecdsa:
    //          digitally-signed struct {
    //              opaque sha_hash[sha_size];
    //          };
    //  } Signature;


    //ServerKeyExchange.signed_params.sha_hash
    //    SHA(ClientHello.random + ServerHello.random +
    //                                      ServerKeyExchange.params);


    //    struct {
    //   SignatureAndHashAlgorithm algorithm;
    //   opaque signature<0..2^16-1>;
    //} DigitallySigned;

    internal class ECDHEServerKeyExchange : IHandshakeMessage
	{
        private readonly byte[] _ServerParams;

        public THandshakeType MessageType => THandshakeType.ServerKeyExchange;

        public TEllipticCurveType EllipticCurveType { get; private set; }

        public TEllipticCurve EllipticCurve { get; private set; }

        public byte[] PublicKeyBytes { get; private set; }

        public THashAlgorithm HashAlgorithm { get; private set; }

        public TSignatureAlgorithm SignatureAlgorithm { get; private set; }

        public byte[] Signature { get; private set; }

        public ECDHEServerKeyExchange() => this.EllipticCurveType = TEllipticCurveType.NamedCurve;

        public ECDHEServerKeyExchange(ECDHEKeyExchange keyExchange, THashAlgorithm hashAlgorithm, 
            TSignatureAlgorithm signatureAlgorithm, AsymmetricKeyParameter serverPrivateKey)
		{
            if(keyExchange == null)
            {
                throw new ArgumentNullException(nameof(keyExchange));
            }

            if(serverPrivateKey == null)
            {
                throw new ArgumentNullException(nameof(serverPrivateKey));
            }

            this.EllipticCurveType = TEllipticCurveType.NamedCurve;
            this.EllipticCurve = keyExchange.Curve;
            this.HashAlgorithm = hashAlgorithm;
            this.SignatureAlgorithm = signatureAlgorithm;

			var stream = new System.IO.MemoryStream();
			stream.WriteByte((byte)this.EllipticCurveType);
			NetworkByteOrderConverter.WriteUInt16(stream, (ushort)this.EllipticCurve);
			var pointEncoded = keyExchange.PublicKey.Q.GetEncoded(false);
			stream.WriteByte((byte)pointEncoded.Length);
			stream.Write(pointEncoded, 0, pointEncoded.Length);
            this._ServerParams = stream.ToArray();


			//IDigest hashMD5 = GetDigest(THashAlgorithm.MD5);
			//IDigest hashSHA = GetDigest(THashAlgorithm.SHA1);
			//int size = hashMD5.GetDigestSize();
			//byte[] hash = new byte[size + hashSHA.GetDigestSize()];
			//hashMD5.BlockUpdate(clientRandom.RandomBytes, 0, clientRandom.RandomBytes.Length);
			//hashMD5.BlockUpdate(serverRandom.RandomBytes, 0, serverRandom.RandomBytes.Length);
			//hashMD5.BlockUpdate(_ServerParams, 0, _ServerParams.Length);
			//hashMD5.DoFinal(hash, 0);
			//hashSHA.BlockUpdate(clientRandom.RandomBytes, 0, clientRandom.RandomBytes.Length);
			//hashSHA.BlockUpdate(serverRandom.RandomBytes, 0, serverRandom.RandomBytes.Length);
			//hashSHA.BlockUpdate(_ServerParams, 0, _ServerParams.Length);
			//hashSHA.DoFinal(hash, size);

			//ISigner signer = GetSigner(signatureAlgorithm, THashAlgorithm.None, serverPrivateKey);
			//signer.BlockUpdate(hash, 0, hash.Length);
			//_Signature = signer.GenerateSignature();

			var signer = this.GetSigner(signatureAlgorithm, hashAlgorithm, serverPrivateKey);
			var clientRandomBytes = keyExchange.ClientRandom.Serialise();
			var serverRandomBytes = keyExchange.ServerRandom.Serialise();
			signer.BlockUpdate(clientRandomBytes, 0, clientRandomBytes.Length);
			signer.BlockUpdate(serverRandomBytes, 0, serverRandomBytes.Length);
			signer.BlockUpdate(this._ServerParams, 0, this._ServerParams.Length);
            this.Signature = signer.GenerateSignature();
		}

		public int CalculateSize(Version version)
		{
            if(version == null)
            {
                throw new ArgumentNullException(nameof(version));
            }

			var result = 0;
			if (this._ServerParams != null)
			{
				result += this._ServerParams.Length;
			}

			if (this.Signature != null)
			{
				if (version >= DTLSRecord.Version1_2)
                {
                    result += 2;
                }

                result += 2;
				result += this.Signature.Length;				
			}

			return result;
		}

        public static ECDHEServerKeyExchange Deserialise(Stream stream, Version version)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (version == null)
            {
                throw new ArgumentNullException(nameof(version));
            }

            var result = new ECDHEServerKeyExchange
            {
                EllipticCurveType = (TEllipticCurveType)stream.ReadByte(),
                EllipticCurve = (TEllipticCurve)NetworkByteOrderConverter.ToUInt16(stream)
            };

            var length = stream.ReadByte();
			if (length > 0)
			{
				result.PublicKeyBytes = new byte[length];
				stream.Read(result.PublicKeyBytes, 0, length);
			}

            if (version >= DTLSRecord.Version1_2)
            {
                result.HashAlgorithm = (THashAlgorithm)stream.ReadByte();
                result.SignatureAlgorithm = (TSignatureAlgorithm)stream.ReadByte();
            }

            int signatureLength = NetworkByteOrderConverter.ToUInt16(stream);
            if (signatureLength > 0)
            {
                result.Signature = new byte[signatureLength];
                stream.Read(result.Signature, 0, signatureLength);
            }

            return result;
        }

		public void Serialise(Stream stream, Version version)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (version == null)
            {
                throw new ArgumentNullException(nameof(version));
            }

            if (this._ServerParams != null)
			{
				stream.Write(this._ServerParams, 0, this._ServerParams.Length);
			}

			if (version >= DTLSRecord.Version1_2)
			{
				stream.WriteByte((byte)this.HashAlgorithm);
				stream.WriteByte((byte)this.SignatureAlgorithm);
			}

			if (this.Signature != null)
			{
				NetworkByteOrderConverter.WriteUInt16(stream, (ushort)this.Signature.Length);
				stream.Write(this.Signature, 0, this.Signature.Length);
			}
		}
        
		private IDigest GetDigest(THashAlgorithm hashAlgorithm)
		{
			IDigest result = null;
			switch (hashAlgorithm)
			{
				case THashAlgorithm.None:
					result = new NullDigest();
					break;
				case THashAlgorithm.MD5:
					result = new MD5Digest();
					break;
				case THashAlgorithm.SHA1:
					result = new Sha1Digest();
					break;
				case THashAlgorithm.SHA224:
					result = new Sha224Digest();
					break;
				case THashAlgorithm.SHA256:
					result = new Sha256Digest();
					break;
				case THashAlgorithm.SHA384:
					result = new Sha384Digest();
					break;
				case THashAlgorithm.SHA512:
					result = new Sha512Digest();
					break;
				default:
					break;
			}
			return result;
		}

		private ISigner GetSigner(TSignatureAlgorithm signatureAlgorithm, THashAlgorithm hashAlgorithm, AsymmetricKeyParameter serverPrivateKey)
		{
            if(serverPrivateKey == null)
            {
                throw new ArgumentNullException(nameof(serverPrivateKey));
            }

			ISigner result = null;
			switch (signatureAlgorithm)
			{
				case TSignatureAlgorithm.Anonymous:
                    {
                        break;
                    }
				case TSignatureAlgorithm.RSA:
                    {
                        break;
                    }
				case TSignatureAlgorithm.DSA:
                    {
                        break;
                    }
				case TSignatureAlgorithm.ECDSA:
                    {
                        result = new DsaDigestSigner(new ECDsaSigner(), this.GetDigest(hashAlgorithm));
                        break;
                    }
				default:
                    {
                        break;
                    }
			}
			result.Init(true, serverPrivateKey);
			//result.Init(true, new ParametersWithRandom(serverPrivateKey, this.mContext.SecureRandom));
			return result;
		}
	}
}