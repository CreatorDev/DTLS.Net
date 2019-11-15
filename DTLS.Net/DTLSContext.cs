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

using Org.BouncyCastle.Crypto.Prng;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities;
using System;

using BcTls = Org.BouncyCastle.Crypto.Tls;

namespace DTLS
{
    internal class DTLSContext : TlsContext
	{
		private class DTLSSecurityParameters : SecurityParameters
		{
            private readonly HandshakeInfo _HandshakeInfo;
			private readonly byte[] _ClientRandom;
			private readonly byte[] _ServerRandom;
            private readonly int _PrfAlgorithm;

            public override int CipherSuite => (int)this._HandshakeInfo.CipherSuite;
            public override byte[] ClientRandom => this._ClientRandom;
            public override byte[] MasterSecret => this._HandshakeInfo.MasterSecret;
            public override int PrfAlgorithm => this._PrfAlgorithm;
            public override byte[] ServerRandom => this._ServerRandom;

            public DTLSSecurityParameters(Version version, HandshakeInfo handshakeInfo)
			{
                if (version == null)
                {
                    throw new ArgumentNullException(nameof(version));
                }
                
                this._HandshakeInfo = handshakeInfo;
                if (handshakeInfo != null)
                {
                    this._ClientRandom = handshakeInfo.ClientRandom.Serialise();
                    this._ServerRandom = handshakeInfo.ServerRandom.Serialise();
                }

                switch (CipherSuites.GetPseudorandomFunction(version, handshakeInfo.CipherSuite))
                {
                    case TPseudorandomFunction.NotSet:
                        {
                            break;
                        }
                    case TPseudorandomFunction.Legacy:
                        {
                            this._PrfAlgorithm = BcTls.PrfAlgorithm.tls_prf_legacy;
                            break;
                        }
                    case TPseudorandomFunction.SHA256:
                        {
                            this._PrfAlgorithm = BcTls.PrfAlgorithm.tls_prf_sha256;
                            break;
                        }
                    case TPseudorandomFunction.SHA384:
                        {
                            this._PrfAlgorithm = BcTls.PrfAlgorithm.tls_prf_sha384;
                            break;
                        }
                    default:
                        {
                            break;
                        }
                }
			}
    	}
        
        public ProtocolVersion ClientVersion { get; private set; }
        public bool IsServer { get; private set; }
		public IRandomGenerator NonceRandomGenerator { get; private set; }
        public SecureRandom SecureRandom { get;  set; }
        public SecurityParameters SecurityParameters { get; private set; }
		public ProtocolVersion ServerVersion { get; private set; }
		public object UserObject
        {
            get => throw new NotImplementedException();
            set => throw new NotImplementedException();
        }

        public DTLSContext() { }

        public DTLSContext(bool client, Version version, HandshakeInfo handshakeInfo)
        {
            this.IsServer = !client;
            if (version == DTLSRecord.Version1_2)
            {
                this.ClientVersion = ProtocolVersion.DTLSv12;
                this.ServerVersion = ProtocolVersion.DTLSv12;
            }
            else
            {
                this.ClientVersion = ProtocolVersion.DTLSv10;
                this.ServerVersion = ProtocolVersion.DTLSv10;
            }
            this.SecurityParameters = new DTLSSecurityParameters(version, handshakeInfo);
            this.NonceRandomGenerator = new DigestRandomGenerator(TlsUtilities.CreateHash(HashAlgorithm.sha256));
            this.NonceRandomGenerator.AddSeedMaterial(Times.NanoTime());

        }

        public byte[] ExportKeyingMaterial(string asciiLabel, byte[] context_value, int length) => throw new NotImplementedException();

        public TlsSession ResumableSession => throw new NotImplementedException();
	}
}