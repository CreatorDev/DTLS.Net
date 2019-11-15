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
    //enum
    //{
    //    rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
    //    rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
    //    fortezza_dms_RESERVED(20), (255)
    //}ClientCertificateType;

    //opaque DistinguishedName<1..2^16-1>;

    //struct 
    //{
    //       ClientCertificateType certificate_types<1..2^8-1>;
    //       SignatureAndHashAlgorithm  supported_signature_algorithms<2^16-1>;
    //       DistinguishedName certificate_authorities<0..2^16-1>;
    //}CertificateRequest;


    // DTLS 1.0
    //struct {
    //      ClientCertificateType certificate_types<1..2^8-1>;
    //    DistinguishedName certificate_authorities<0..2^16-1>;
    //}
    //CertificateRequest;

    internal class CertificateRequest : IHandshakeMessage
    {
        public THandshakeType MessageType => THandshakeType.CertificateRequest;

        public List<TClientCertificateType> CertificateTypes { get; private set; }
        public List<SignatureHashAlgorithm> SupportedAlgorithms { get; private set; }
        public List<byte[]> CertificateAuthorities { get; private set; }

        public CertificateRequest()
        {
            this.CertificateTypes = new List<TClientCertificateType>();
            this.SupportedAlgorithms = new List<SignatureHashAlgorithm>();
            this.CertificateAuthorities = new List<byte[]>();
        }

        public int CalculateSize(Version version)
        {
            if(version == null)
            {
                throw new ArgumentNullException(nameof(version));
            }

            var result = 3 + this.CertificateTypes.Count;
            if (version >= DTLSRecord.Version1_2)
            {
                result += 2;
                result += (this.SupportedAlgorithms.Count * 2);
            }
            if (this.CertificateAuthorities.Count > 0)
            {
                foreach (var item in this.CertificateAuthorities)
                {
                    result += item.Length;
                }
            }
            return result;
        }

        public static CertificateRequest Deserialise(Stream stream, Version version)
        {
            if(stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            if (version == null)
            {
                throw new ArgumentNullException(nameof(version));
            }

            var result = new CertificateRequest();
            var certificateTypeCount = stream.ReadByte();
            if (certificateTypeCount > 0)
            {
                for (var index = 0; index < certificateTypeCount; index++)
                {
                    result.CertificateTypes.Add((TClientCertificateType)stream.ReadByte());
                }
            }

            if (version >= DTLSRecord.Version1_2)
            {
                var length = NetworkByteOrderConverter.ToUInt16(stream);
                var supportedAlgorithmsLength = (ushort)(length / 2);
                if (supportedAlgorithmsLength > 0)
                {
                    for (uint index = 0; index < supportedAlgorithmsLength; index++)
                    {
                        var hash = (THashAlgorithm)stream.ReadByte();
                        var signature = (TSignatureAlgorithm)stream.ReadByte();
                        result.SupportedAlgorithms.Add(new SignatureHashAlgorithm() { Hash = hash, Signature = signature });
                    }
                }
            }

            var certificateAuthoritiesLength = NetworkByteOrderConverter.ToUInt16(stream);
            if (certificateAuthoritiesLength > 0)
            {
                var read = 0;
                while(certificateAuthoritiesLength > read)
                {
                    var distinguishedNameLength = NetworkByteOrderConverter.ToUInt16(stream);
                    read += (2 + distinguishedNameLength);
                    var distinguishedName = new byte[distinguishedNameLength];
                    stream.Read(distinguishedName, 0, distinguishedNameLength);
                    result.CertificateAuthorities.Add(distinguishedName);
                }
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

            stream.WriteByte((byte)this.CertificateTypes.Count);
            foreach (var item in this.CertificateTypes)
            {
                stream.WriteByte((byte)item);
            }

            if (version >= DTLSRecord.Version1_2)
            {
                NetworkByteOrderConverter.WriteUInt16(stream, (ushort)(this.SupportedAlgorithms.Count * 2));
                foreach (var item in this.SupportedAlgorithms)
                {
                    stream.WriteByte((byte)item.Hash);
                    stream.WriteByte((byte)item.Signature);
                }
            }

            ushort certificateAuthoritiesSize = 0;
            if (this.CertificateAuthorities.Count > 0)
            {
                foreach (var item in this.CertificateAuthorities)
                {
                    certificateAuthoritiesSize += (ushort)item.Length;
                }
            }

            NetworkByteOrderConverter.WriteUInt16(stream, certificateAuthoritiesSize);
            if (this.CertificateAuthorities.Count > 0)
            {
                foreach (var item in this.CertificateAuthorities)
                {
                    NetworkByteOrderConverter.WriteUInt16(stream, (ushort)item.Length);
                    stream.Write(item, 0, item.Length);
                }
            }
        }
    }
}