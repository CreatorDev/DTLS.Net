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
	internal class CipherSuites
	{
        private class CipherSuite
        {
            public TCipherSuite Suite { get; set; }
            public TKeyExchangeAlgorithm KeyExchangeAlgorithm { get; set; }
            //public TEncryptionAlgorithm EncryptionAlgorithm { get; set; }
            public TSignatureAlgorithm SignatureAlgorithm { get; set; }
            public Version MinVersion { get; set; }
            public TPseudorandomFunction PRF { get; set; }

            public CipherSuite(TCipherSuite cipherSuite, TKeyExchangeAlgorithm keyExchangeAlgorithm, TSignatureAlgorithm signatureAlgorithm, Version minVersion,TPseudorandomFunction prf)
            {
                Suite = cipherSuite;
                KeyExchangeAlgorithm = keyExchangeAlgorithm;
                SignatureAlgorithm = signatureAlgorithm;
                MinVersion = minVersion;
                PRF = prf;
            }
        }

        private static Dictionary<TCipherSuite, CipherSuite> _CipherSuites;

        static CipherSuites()
        {
            _CipherSuites = new Dictionary<TCipherSuite, CipherSuite>();
            _CipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, new CipherSuite(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8, TKeyExchangeAlgorithm.ECDHE_ECDSA, TSignatureAlgorithm.ECDSA, DTLSRecord.Version1_2, TPseudorandomFunction.SHA256));
            _CipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, new CipherSuite(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256, TKeyExchangeAlgorithm.ECDHE_ECDSA, TSignatureAlgorithm.ECDSA, DTLSRecord.Version1_0, TPseudorandomFunction.SHA256));
            _CipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8, new CipherSuite(TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8, TKeyExchangeAlgorithm.PSK, TSignatureAlgorithm.Anonymous, DTLSRecord.Version1_2, TPseudorandomFunction.SHA256));
            _CipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256, new CipherSuite(TCipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256, TKeyExchangeAlgorithm.PSK, TSignatureAlgorithm.Anonymous, DTLSRecord.Version1_0, TPseudorandomFunction.SHA256));
            _CipherSuites.Add(TCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, new CipherSuite(TCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256, TKeyExchangeAlgorithm.ECDHE_PSK, TSignatureAlgorithm.Anonymous, DTLSRecord.Version1_0, TPseudorandomFunction.SHA256));
        }


		public static TKeyExchangeAlgorithm GetKeyExchangeAlgorithm(TCipherSuite cipherSuite)
		{
			TKeyExchangeAlgorithm result = TKeyExchangeAlgorithm.NotSet;
            CipherSuite suite;
            if (_CipherSuites.TryGetValue(cipherSuite, out suite))
            {
                result = suite.KeyExchangeAlgorithm;
            }
			return result;
		}

        public static TPseudorandomFunction GetPseudorandomFunction(Version version, TCipherSuite cipherSuite)
        {
            TPseudorandomFunction result = TPseudorandomFunction.Legacy;
            if (version >= DTLSRecord.Version1_2)
            {
                CipherSuite suite;
                if (_CipherSuites.TryGetValue(cipherSuite, out suite))
                {
                    result = suite.PRF;
                }
            }
            return result;
        }

		public static TSignatureAlgorithm GetSignatureAlgorithm(TCipherSuite cipherSuite)
		{
			TSignatureAlgorithm result = TSignatureAlgorithm.Anonymous;
            CipherSuite suite;
            if (_CipherSuites.TryGetValue(cipherSuite, out suite))
            {
                result = suite.SignatureAlgorithm;
            }
			return result;
		}

        public static bool SuiteUsable(TCipherSuite cipherSuite, Org.BouncyCastle.Crypto.AsymmetricKeyParameter privateKey, PSKIdentities pskIdentities, bool haveValidatePSKCallback)
        {
            bool result = false;
            TKeyExchangeAlgorithm keyExchangeAlgorithm = GetKeyExchangeAlgorithm(cipherSuite);
            switch (keyExchangeAlgorithm)
            {
                case TKeyExchangeAlgorithm.NotSet:
                    break;
                case TKeyExchangeAlgorithm.PSK:
                case TKeyExchangeAlgorithm.ECDHE_PSK:
                    result = haveValidatePSKCallback || ((pskIdentities != null) && (pskIdentities.Count > 0));
                    break;
                case TKeyExchangeAlgorithm.ECDH_ECDSA:
                case TKeyExchangeAlgorithm.ECDHE_ECDSA:
                    result = (privateKey != null);
                    break;
                default:
                    break;
            }
            return result;
        }

        public static bool SupportedVersion(TCipherSuite cipherSuite, Version version)
        {
            bool result = false;
            CipherSuite suite;
            if (_CipherSuites.TryGetValue(cipherSuite, out suite))
            {
                result = suite.MinVersion <= version;
            }
            return result;
        }




    }
}
