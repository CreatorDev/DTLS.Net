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


    //struct {
    //         SignatureAndHashAlgorithm algorithm;
    //    opaque signature<0..2^16-1>;
    //}DigitallySigned;


    //struct {
    //    Signature signature;
    //}CertificateVerify;

    //CertificateVerify.signature.md5_hash
    //    MD5(handshake_messages);

    //CertificateVerify.signature.sha_hash
    //    SHA(handshake_messages);

    //struct {
    //       digitally-signed struct {
    //           opaque handshake_messages[handshake_messages_length];
    //        }
    //  } CertificateVerify;
    internal class CertificateVerify : IHandshakeMessage
    {
        public THandshakeType MessageType => THandshakeType.CertificateVerify;

        public SignatureHashAlgorithm SignatureHashAlgorithm { get; set; }

        public byte[] Signature { get; set; }

        public int CalculateSize(Version version)
        {
            if (version == null)
            {
                throw new ArgumentNullException(nameof(version));
            }

            var result = 2;
            if(version > DTLSRecord.Version1_0)
            {
                result += 2;
            }

            if (this.Signature != null)
            {
                result += this.Signature.Length;
            }
            return result;
        }

        public static CertificateVerify Deserialise(Stream stream, Version version)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (version == null)
            {
                throw new ArgumentNullException(nameof(version));
            }

            var result = new CertificateVerify();

            if (version > DTLSRecord.Version1_0)
            {
                var hash = (THashAlgorithm)stream.ReadByte();
                var signature = (TSignatureAlgorithm)stream.ReadByte();
                result.SignatureHashAlgorithm = new SignatureHashAlgorithm() { Hash = hash, Signature = signature };
            }

            var length = NetworkByteOrderConverter.ToUInt16(stream);
            if (length > 0)
            {
                result.Signature = new byte[length];
                stream.Read(result.Signature, 0, length);
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

            if (version > DTLSRecord.Version1_0)
            {
                stream.WriteByte((byte)this.SignatureHashAlgorithm.Hash);
                stream.WriteByte((byte)this.SignatureHashAlgorithm.Signature);
            }

            if (this.Signature == null)
            {
                NetworkByteOrderConverter.WriteUInt16(stream, 0);
            }
            else
            {
                NetworkByteOrderConverter.WriteUInt16(stream, (ushort)this.Signature.Length);
                stream.Write(this.Signature, 0, this.Signature.Length);
            }
        }
    }
}