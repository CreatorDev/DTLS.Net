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
using Org.BouncyCastle.Crypto.Tls;

namespace DTLS
{
    internal class TLSUtils
	{
        public static DateTime UnixEpoch = new DateTime(1970, 1, 1);

		private static byte[] MASTER_SECRET_LABEL;
		private const int MASTER_SECRET_LENGTH = 48;
		private static TlsCipherFactory CipherFactory;

		static TLSUtils()
		{
			MASTER_SECRET_LABEL = Encoding.ASCII.GetBytes("master secret");
			CipherFactory = new DefaultTlsCipherFactory();
		}

        public static bool ByteArrayCompare(byte[] x, byte[] y)
        {
            bool result = true;
            if (x.Length == y.Length)
            {
                for (int index = 0; index < x.Length; index++)
                {
                    if (x[index] != y[index])
                    {
                        result = false;
                        break;
                    }
                }
            }
            else
                result = false;
            return result;
        }      

		public static byte[] CalculateMasterSecret(byte[] preMasterSecret, IKeyExchange keyExchange)
		{
			byte[] result;
			byte[] clientRandom = keyExchange.ClientRandom.Serialise();
			byte[] serverRandom = keyExchange.ServerRandom.Serialise();
			byte[] seed = new byte[MASTER_SECRET_LABEL.Length + clientRandom.Length + serverRandom.Length];
			Buffer.BlockCopy(MASTER_SECRET_LABEL, 0, seed, 0, MASTER_SECRET_LABEL.Length);
			Buffer.BlockCopy(clientRandom, 0, seed, MASTER_SECRET_LABEL.Length, clientRandom.Length);
			Buffer.BlockCopy(serverRandom, 0, seed, MASTER_SECRET_LABEL.Length + clientRandom.Length, serverRandom.Length);
			result = PseudorandomFunction(preMasterSecret, seed, MASTER_SECRET_LENGTH);
			Array.Clear(preMasterSecret, 0, preMasterSecret.Length);
			return result;
		}
              
		public static byte[] PseudorandomFunction(byte[] secret, byte[] seed, int length)
		{
			byte[] result = new byte[length];
			System.Security.Cryptography.HMACSHA256 hmac = new System.Security.Cryptography.HMACSHA256(secret);
			int iterations = (int)Math.Ceiling(length / (double)hmac.HashSize);
			byte[] dataToHash = seed;
			int offset = 0;
			for (int index = 0; index < iterations; index++)
			{
				dataToHash = hmac.ComputeHash(dataToHash);
				hmac.TransformBlock(dataToHash, 0, dataToHash.Length, dataToHash, 0);
				byte[] hash = hmac.TransformFinalBlock(seed, 0, seed.Length);
				Buffer.BlockCopy(hash, 0, result, offset, Math.Min(hash.Length, length - offset));
				offset += hash.Length;
			}
			return result;
		}

		private static int GetEncryptionAlgorithm(TCipherSuite cipherSuite)
		{
			int result = 0;
			if (cipherSuite == TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				result = EncryptionAlgorithm.AES_128_CCM_8;
			else if (cipherSuite == TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
				result = EncryptionAlgorithm.AES_128_CBC;
			else if (cipherSuite == TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
				result = EncryptionAlgorithm.AES_128_CCM_8;
			else if (cipherSuite == TCipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256)
				result = EncryptionAlgorithm.AES_128_CBC;
			else if (cipherSuite == TCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256)
				result = EncryptionAlgorithm.AES_128_CBC;
			return result;
		}

		private static int GetMACAlgorithm(TCipherSuite cipherSuite)
		{
			int result = 0;
			if (cipherSuite == TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8)
				result = MacAlgorithm.cls_null;
			else if (cipherSuite == TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256)
				result = MacAlgorithm.hmac_sha256;
			else if (cipherSuite == TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8)
				result = MacAlgorithm.cls_null;
			else if (cipherSuite == TCipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256)
				result = MacAlgorithm.hmac_sha256;
			else if (cipherSuite == TCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256)
				result = MacAlgorithm.hmac_sha256;
			return result;
		}

        public static TlsCipher AssignCipher(byte[] preMasterSecret, bool client, Version version, HandshakeInfo handshakeInfo)
        {
            int encryptionAlgorithm = GetEncryptionAlgorithm(handshakeInfo.CipherSuite);
            int macAlgorithm = GetMACAlgorithm(handshakeInfo.CipherSuite);
            TlsContext context = new DTLSContext(client, version, handshakeInfo);
            SecurityParameters securityParameters = context.SecurityParameters;
            byte[] seed = Concat(securityParameters.ClientRandom, securityParameters.ServerRandom);
            string asciiLabel = ExporterLabel.master_secret;
            handshakeInfo.MasterSecret = TlsUtilities.PRF(context, preMasterSecret, asciiLabel, seed, 48);
            //session.Handshake.MasterSecret = TlsUtilities.PRF_legacy(preMasterSecret, asciiLabel, seed, 48);
#if DEBUG
            Console.Write("MasterSecret :");
            WriteToConsole(handshakeInfo.MasterSecret);
#endif

            seed = Concat(securityParameters.ServerRandom, securityParameters.ClientRandom);
            byte[] key_block = TlsUtilities.PRF(context, handshakeInfo.MasterSecret, ExporterLabel.key_expansion, seed, 96);
            //byte[] key_block = TlsUtilities.PRF_legacy(session.Handshake.MasterSecret, ExporterLabel.key_expansion, seed, 96);
#if DEBUG
            Console.Write("Key block :");
            WriteToConsole(key_block);
#endif
            return CipherFactory.CreateCipher(context, encryptionAlgorithm, macAlgorithm);
        }

        public static byte[] Sign(Org.BouncyCastle.Crypto.AsymmetricKeyParameter privateKey, bool client, Version version, HandshakeInfo handshakeInfo, SignatureHashAlgorithm signatureHashAlgorithm, byte[] hash)
        {
            TlsSigner signer = null;
            switch (signatureHashAlgorithm.Signature)
            {
                case TSignatureAlgorithm.Anonymous:
                    break;
                case TSignatureAlgorithm.RSA:
                    signer = new TlsRsaSigner();
                    break;
                case TSignatureAlgorithm.DSA:
                    signer = new TlsDssSigner();
                    break;
                case TSignatureAlgorithm.ECDSA:

                    signer = new TlsECDsaSigner();
                    break;
                default:
                    break;
            }
            DTLSContext context = new DTLSContext(client, version, handshakeInfo);
            Net.Util.DTLSCryptoApiRandomGenerator randomGenerator = new Net.Util.DTLSCryptoApiRandomGenerator();
            context.SecureRandom = new Org.BouncyCastle.Security.SecureRandom(randomGenerator);

            signer.Init(context);
            if (TlsUtilities.IsTlsV12(context))
            {
                SignatureAndHashAlgorithm signatureAndHashAlgorithm = new SignatureAndHashAlgorithm((byte)signatureHashAlgorithm.Hash, (byte)signatureHashAlgorithm.Signature);
                return signer.GenerateRawSignature(signatureAndHashAlgorithm, privateKey, hash);
            }
            else
            {
                return signer.GenerateRawSignature(privateKey, hash);
            }
        }


        internal static byte[] Concat(byte[] a, byte[] b)
		{
			byte[] c = new byte[a.Length + b.Length];
			Array.Copy(a, 0, c, 0, a.Length);
			Array.Copy(b, 0, c, a.Length, b.Length);
			return c;
		}

        public static void WriteToConsole(byte[] data)
        {
            Console.Write("0x");
            foreach (byte item in data)
            {
                byte b = ((byte)(item >> 4));
				Console.Write((char)(b > 9 ? b + 0x37 : b + 0x30));
                b = ((byte)(item & 0xF));
				Console.Write((char)(b > 9 ? b + 0x37 : b + 0x30));
            } 
            Console.WriteLine();
        }

        public static byte[] GetVerifyData(Version version, HandshakeInfo handshakeInfo, bool client, bool isClientFinished, byte[] handshakeHash)
        {
            string asciiLabel;
            TlsContext context = new DTLSContext(client, version, handshakeInfo);
            if (isClientFinished)
                asciiLabel = ExporterLabel.client_finished;
            else
                asciiLabel = ExporterLabel.server_finished;
            //return TlsUtilities.PRF_legacy(masterSecret, asciiLabel, handshakeHash, 12);
            return TlsUtilities.PRF(context, handshakeInfo.MasterSecret, asciiLabel, handshakeHash, 12);
        }

        internal static byte[] GetPSKPreMasterSecret(byte[] otherSecret, byte[] psk)
        {
            byte[] result = new byte[4 + otherSecret.Length + psk.Length];
            NetworkByteOrderConverter.WriteUInt16(result, 0, (ushort)otherSecret.Length);
            Buffer.BlockCopy(otherSecret, 0, result, 2, otherSecret.Length);
            NetworkByteOrderConverter.WriteUInt16(result, 2 + otherSecret.Length, (ushort)psk.Length);
            Buffer.BlockCopy(psk, 0, result, 4 + otherSecret.Length, psk.Length);
            return result;
        }
    }
}
