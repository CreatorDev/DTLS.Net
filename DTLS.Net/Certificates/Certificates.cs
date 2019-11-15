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

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using Org.BouncyCastle.X509;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace DTLS
{
    public static class Certificates
    {

        private static void AddStandardCertificateInfo(X509V3CertificateGenerator certificateGenerator, SecureRandom random,
            CertificateSubject subject, CertificateSubject issuer, DateTime startDate, DateTime expiryDate)
        {
            if (certificateGenerator == null)
            {
                throw new ArgumentNullException(nameof(certificateGenerator));
            }

            if (random == null)
            {
                throw new ArgumentNullException(nameof(random));
            }

            if (subject == null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            if (issuer == null)
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(Int64.MaxValue), random);
            certificateGenerator.SetSerialNumber(serialNumber);

            certificateGenerator.SetIssuerDN(GetName(issuer));
            certificateGenerator.SetSubjectDN(GetName(subject));

            certificateGenerator.SetNotBefore(startDate);
            certificateGenerator.SetNotAfter(expiryDate);
        }

        private static byte[] ExportCertificate(X509Certificate certificate, AsymmetricCipherKeyPair subjectKeyPair, TCertificateFormat certificateFormat)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            if (subjectKeyPair == null)
            {
                throw new ArgumentNullException(nameof(subjectKeyPair));
            }

            byte[] result = null;
            switch (certificateFormat)
            {
                case TCertificateFormat.NotSet:
                    {
                        break;
                    }
                case TCertificateFormat.PEM:
                    {
                        using (var stream = new MemoryStream())
                        {
                            using (var writer = new StreamWriter(stream))
                            {
                                var pemWriter = new PemWriter(writer);
                                if (subjectKeyPair.Private is ECKeyParameters)
                                {
                                    var priv = (ECPrivateKeyParameters)subjectKeyPair.Private;
                                    var dp = priv.Parameters;
                                    var orderBitLength = dp.N.BitLength;
                                    ECPrivateKeyStructure ec;
                                    X962Parameters x962;
                                    if (priv.PublicKeyParamSet == null)
                                    {
                                        var ecP = new X9ECParameters(dp.Curve, dp.G, dp.N, dp.H, dp.GetSeed());
                                        x962 = new X962Parameters(ecP);
                                    }
                                    else
                                    {
                                        x962 = new X962Parameters(priv.PublicKeyParamSet);
                                    }
                                    ec = new ECPrivateKeyStructure(orderBitLength, priv.D, SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(subjectKeyPair.Public).PublicKeyData, x962);
                                    pemWriter.WriteObject(new Org.BouncyCastle.Utilities.IO.Pem.PemObject("EC PRIVATE KEY", ec.GetEncoded()));
                                }
                                else
                                {
                                    pemWriter.WriteObject(new MiscPemGenerator(subjectKeyPair.Private));
                                }
                                pemWriter.WriteObject(new MiscPemGenerator(subjectKeyPair.Public));
                                pemWriter.WriteObject(new MiscPemGenerator(certificate));
                                writer.Flush();
                                result = stream.ToArray();
                            }
                        }
                    }
                    break;
                case TCertificateFormat.PFX:
                    {
                        //Asn1Sequence asn1Sequence = Asn1Sequence.GetInstance(Asn1Object.FromByteArray(certificate.GetEncoded()));
                        //asn1Sequence.GetObjects
                        //Org.BouncyCastle.Asn1.Pkcs.Pfx pfx = new Org.BouncyCastle.Asn1.Pkcs.Pfx();
                        //Org.BouncyCastle.Asn1.Pkcs.PrivateKeyInfo info = Org.BouncyCastle.Pkcs.PrivateKeyInfoFactory.CreatePrivateKeyInfo(subjectKeyPair.Private);
                        //result = pfx.GetEncoded(Asn1Encodable.Der);
                        break;
                    }
                case TCertificateFormat.CER:
                    {
                        result = certificate.GetEncoded();
                        break;
                    }
                default:
                    {
                        break;
                    }
            }
            return result;
        }

        private static AsymmetricCipherKeyPair GenerateKeys(X509V3CertificateGenerator certificateGenerator, SecureRandom random,
            SignatureHashAlgorithm signatureAlgorithm)
        {
            if (certificateGenerator == null)
            {
                throw new ArgumentNullException(nameof(certificateGenerator));
            }

            if (random == null)
            {
                throw new ArgumentNullException(nameof(random));
            }

            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }

            AsymmetricCipherKeyPair result = null;
            switch (signatureAlgorithm.Signature)
            {
                case TSignatureAlgorithm.Anonymous:
                    {
                        break;
                    }
                case TSignatureAlgorithm.RSA:
                    {
                        var keyGenerationParameters = new KeyGenerationParameters(random, 2048);
                        var rsaKeyPairGenerator = new RsaKeyPairGenerator();
                        rsaKeyPairGenerator.Init(keyGenerationParameters);
                        result = rsaKeyPairGenerator.GenerateKeyPair();
                        break;
                    }
                case TSignatureAlgorithm.DSA:
                    {
                        break;
                    }
                case TSignatureAlgorithm.ECDSA:
                    {
                        //ECDomainParameters ellipticCurveParameters = EllipticCurveFactory.GetEllipticCurveParameters(TEllipticCurve.secp256r1);
                        var keyPairGenerator = new ECKeyPairGenerator();
                        //keyPairGenerator.Init(new ECKeyGenerationParameters(ellipticCurveParameters, random));
                        keyPairGenerator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, random));
                        result = keyPairGenerator.GenerateKeyPair();
                        //certificateGenerator.AddExtension(X509Extensions.SubjectPublicKeyInfo)
                        //PrivateKey = (ECPrivateKeyParameters)keys.Private;
                        //PublicKey = (ECPublicKeyParameters)keys.Public;
                        break;
                    }
                default:
                    {
                        break;
                    }
            }

            certificateGenerator.SetPublicKey(result.Public);
            return result;
        }

        public static byte[] GenerateCertificate(CertificateSubject subject, CertificateInfo issuer, DateTime startDate,
            DateTime expiryDate, SignatureHashAlgorithm signatureAlgorithm, TCertificateFormat certificateFormat)
        {
            if (subject == null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            if (issuer == null)
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            if (!(issuer.PrivateKey is AsymmetricKeyParameter privateKey))
            {
                return null;
            }

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var certificateGenerator = new X509V3CertificateGenerator();
            AddStandardCertificateInfo(certificateGenerator, random, subject, issuer.Subject, startDate, expiryDate);
            var subjectKeyPair = GenerateKeys(certificateGenerator, random, signatureAlgorithm);

            var algorithm = GetAlgorithm(signatureAlgorithm);

            certificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(false));
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyEncipherment));
            certificateGenerator.AddExtension(X509Extensions.ExtendedKeyUsage, false, new ExtendedKeyUsage(new KeyPurposeID[] { KeyPurposeID.IdKPServerAuth, KeyPurposeID.IdKPClientAuth }));
            var subjectKeyID = new byte[20];
            random.NextBytes(subjectKeyID, 0, 20);
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(subjectKeyID));
            if (issuer.SubjectKeyID != null)
            {
                certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(issuer.SubjectKeyID));
            }

            //if ((subject.AlternativeNames != null) && (subject.AlternativeNames.Count > 0))
            //{
            //    certificateGenerator.AddExtension(X509Extensions.SubjectAlternativeName, true, new SubjectAlternativeNames(false));
            //    //SubjectAlternativeName
            //    //GeneralName.DirectoryName
            //    //GeneralName.IPAddress
            //}

            var certificate = certificateGenerator.Generate(new Asn1SignatureFactory(algorithm, privateKey, random));
            return ExportCertificate(certificate, subjectKeyPair, certificateFormat);
        }

        public static byte[] GenerateIntermediateCACertificate(CertificateSubject subject, CertificateInfo issuer, DateTime startDate,
            DateTime expiryDate, SignatureHashAlgorithm signatureAlgorithm, TCertificateFormat certificateFormat)
        {
            if (subject == null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            if (issuer == null)
            {
                throw new ArgumentNullException(nameof(issuer));
            }

            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }

            if (!(issuer.PrivateKey is AsymmetricKeyParameter privateKey))
            {
                return null;
            }

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var certificateGenerator = new X509V3CertificateGenerator();
            AddStandardCertificateInfo(certificateGenerator, random, subject, issuer.Subject, startDate, expiryDate);
            var subjectKeyPair = GenerateKeys(certificateGenerator, random, signatureAlgorithm);

            certificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(0));
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign));
            var subjectKeyID = new byte[20];
            random.NextBytes(subjectKeyID, 0, 20);
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(subjectKeyID));
            if (issuer.SubjectKeyID != null)
            {
                certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(issuer.SubjectKeyID));
            }

            var algorithm = GetAlgorithm(signatureAlgorithm);

            var certificate = certificateGenerator.Generate(new Asn1SignatureFactory(algorithm, privateKey, random));

            return ExportCertificate(certificate, subjectKeyPair, certificateFormat);
        }

        public static byte[] GenerateRootCACertificate(CertificateSubject subject, DateTime startDate, DateTime expiryDate,
            SignatureHashAlgorithm signatureAlgorithm, TCertificateFormat certificateFormat)
        {
            if (subject == null)
            {
                throw new ArgumentNullException(nameof(subject));
            }

            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }

            var randomGenerator = new CryptoApiRandomGenerator();
            var random = new SecureRandom(randomGenerator);
            var certificateGenerator = new X509V3CertificateGenerator();
            AddStandardCertificateInfo(certificateGenerator, random, subject, subject, startDate, expiryDate);
            var subjectKeyPair = GenerateKeys(certificateGenerator, random, signatureAlgorithm);

            certificateGenerator.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            certificateGenerator.AddExtension(X509Extensions.KeyUsage, true, new KeyUsage(KeyUsage.DigitalSignature | KeyUsage.KeyCertSign));
            var subjectKeyID = new byte[20];
            random.NextBytes(subjectKeyID, 0, 20);
            certificateGenerator.AddExtension(X509Extensions.SubjectKeyIdentifier, false, new SubjectKeyIdentifier(subjectKeyID));
            certificateGenerator.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(subjectKeyID));

            var algorithm = GetAlgorithm(signatureAlgorithm);
            // selfsign certificate
            var certificate = certificateGenerator.Generate(new Asn1SignatureFactory(algorithm, subjectKeyPair.Private, random));

            return ExportCertificate(certificate, subjectKeyPair, certificateFormat);
        }

        private static string GetAlgorithm(SignatureHashAlgorithm signatureAlgorithm)
        {
            if (signatureAlgorithm == null)
            {
                throw new ArgumentNullException(nameof(signatureAlgorithm));
            }

            // eg "SHA256WithRSA", "SHA224WithECDSA",;
            var result = new StringBuilder();
            result.Append(signatureAlgorithm.Hash.ToString());
            result.Append("With");
            result.Append(signatureAlgorithm.Signature.ToString());
            return result.ToString();
        }

        public static CertificateInfo GetCertificateInfo(byte[] certificate, TCertificateFormat certificateFormat)
        {
            if (certificate == null)
            {
                throw new ArgumentNullException(nameof(certificate));
            }

            CertificateInfo result = null;
            X509CertificateStructure cert = null;
            switch (certificateFormat)
            {
                case TCertificateFormat.NotSet:
                    {
                        break;
                    }
                case TCertificateFormat.PEM:
                    {
                        var reader = new PemReader(new StreamReader(new MemoryStream(certificate)));
                        var pem = reader.ReadPemObject();
                        while (pem != null)
                        {
                            if (pem.Type.EndsWith("CERTIFICATE"))
                            {
                                cert = X509CertificateStructure.GetInstance(pem.Content);
                            }
                            else if (pem.Type.EndsWith("PRIVATE KEY"))
                            {
                                if (result == null)
                                {
                                    result = new CertificateInfo();
                                }

                                result.PrivateKey = GetPrivateKeyFromPEM(pem);
                            }
                            pem = reader.ReadPemObject();
                        }
                        break;
                    }
                case TCertificateFormat.PFX:
                    {
                        break;
                    }
                case TCertificateFormat.CER:
                    {
                        cert = X509CertificateStructure.GetInstance(certificate);
                        break;
                    }
                default:
                    {
                        break;
                    }
            }

            if (cert != null)
            {
                if (result == null)
                {
                    result = new CertificateInfo();
                }

                result.Subject = new CertificateSubject(cert);
                var certX509 = new X509Certificate(cert);
                var subjectKeyID = certX509.GetExtensionValue(X509Extensions.SubjectKeyIdentifier);
                if (subjectKeyID != null)
                {
                    var encodeKeyID = subjectKeyID.GetOctets();
                    var keyID = new byte[encodeKeyID[1]];
                    Buffer.BlockCopy(encodeKeyID, 2, keyID, 0, encodeKeyID[1]);
                    result.SubjectKeyID = keyID;
                }
            }
            return result;
        }

        private static X509Name GetName(CertificateSubject info)
        {
            if (info == null)
            {
                throw new ArgumentNullException(nameof(info));
            }

            var ids = new List<DerObjectIdentifier>();
            var values = new List<string>();
            if (!string.IsNullOrEmpty(info.CommonName))
            {
                ids.Add(X509Name.CN);
                values.Add(info.CommonName);
            }
            if (!string.IsNullOrEmpty(info.Organistion))
            {
                ids.Add(X509Name.O);
                values.Add(info.Organistion);
            }
            if (!string.IsNullOrEmpty(info.OrganistionUnit))
            {
                ids.Add(X509Name.OU);
                values.Add(info.OrganistionUnit);
            }
            if (!string.IsNullOrEmpty(info.Location))
            {
                ids.Add(X509Name.L);
                values.Add(info.Location);
            }
            if (!string.IsNullOrEmpty(info.State))
            {
                ids.Add(X509Name.ST);
                values.Add(info.State);
            }
            if (!string.IsNullOrEmpty(info.Country))
            {
                ids.Add(X509Name.C);
                values.Add(info.Country);
            }
            return new X509Name(ids, values);
        }

        internal static AsymmetricKeyParameter GetPrivateKeyFromPEM(Org.BouncyCastle.Utilities.IO.Pem.PemObject pem)
        {
            if (pem == null)
            {
                throw new ArgumentNullException(nameof(pem));
            }

            if (pem.Type.EndsWith("EC PRIVATE KEY"))
            {
                var sequence = Asn1Sequence.GetInstance(pem.Content);
                var e = sequence.GetEnumerator();
                e.MoveNext();
                var version = ((DerInteger)e.Current).Value;
                PrivateKeyInfo privateKeyInfo;
                if (version.IntValue == 0) //V1
                {
                    privateKeyInfo = PrivateKeyInfo.GetInstance(sequence);
                }
                else
                {
                    var ec = ECPrivateKeyStructure.GetInstance(sequence);
                    var algId = new AlgorithmIdentifier(X9ObjectIdentifiers.IdECPublicKey, ec.GetParameters());
                    privateKeyInfo = new PrivateKeyInfo(algId, ec.ToAsn1Object());
                }
                return PrivateKeyFactory.CreateKey(privateKeyInfo);
            }
            else if (pem.Type.EndsWith("PRIVATE KEY"))
            {
                return PrivateKeyFactory.CreateKey(pem.Content);
            }

            return null;
        }

    }
}
