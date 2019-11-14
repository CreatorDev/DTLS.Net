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

    //    enum { rsa, diffie_hellman } KeyExchangeAlgorithm;

    //struct {
    //    opaque rsa_modulus<1..2^16-1>;
    //    opaque rsa_exponent<1..2^16-1>;
    //} ServerRSAParams;

    //rsa_modulus
    //    The modulus of the server's temporary RSA key.

    //rsa_exponent
    //    The public exponent of the server's temporary RSA key.

    //    struct {
    //    opaque dh_p<1..2^16-1>;
    //    opaque dh_g<1..2^16-1>;
    //    opaque dh_Ys<1..2^16-1>;
    //} ServerDHParams;     /* Ephemeral DH parameters */

    //dh_p
    //    The prime modulus used for the Diffie-Hellman operation.

    //dh_g
    //    The generator used for the Diffie-Hellman operation.

    //dh_Ys
    //  The server's Diffie-Hellman public value (g^X mod p).


    //    struct {
    //    select (KeyExchangeAlgorithm) {
    //        case diffie_hellman:
    //            ServerDHParams params;
    //            Signature signed_params;
    //        case rsa:
    //            ServerRSAParams params;
    //            Signature signed_params;
    //    };
    //} ServerKeyExchange;



    //    struct {
    //    select (SignatureAlgorithm) {
    //        case anonymous: struct { };
    //        case rsa:
    //            digitally-signed struct {
    //                opaque md5_hash[16];
    //                opaque sha_hash[20];
    //            };
    //        case dsa:
    //            digitally-signed struct {
    //                opaque sha_hash[20];
    //            };
    //        };
    //    };
    //} Signature;



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

    internal class ServerKeyExchange : IHandshakeMessage
	{
        public THandshakeType MessageType => THandshakeType.ServerKeyExchange;

        public virtual int CalculateSize(Version version) => 0;

        public virtual void Serialise(Stream stream, Version version) => throw new NotImplementedException();
    }
}