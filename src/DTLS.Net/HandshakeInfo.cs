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
using Org.BouncyCastle.Crypto;

namespace DTLS
{
    internal class HandshakeInfo
    {
        private Org.BouncyCastle.Crypto.Digests.Sha1Digest _VerifyHandshakeSHA1;
        private Org.BouncyCastle.Crypto.Digests.MD5Digest _VerifyHandshakeMD5;
        private IDigest _VerifyHandshake;

        public TCipherSuite CipherSuite { get; set; }

        public RandomData ClientRandom { get; set; }

        public RandomData ServerRandom { get; set; }

        public byte[] MasterSecret { get; set; }

        public IKeyExchange KeyExchange { get; set; }

        public ushort MessageSequence { get; set; }

        public HandshakeInfo()
        {
        }

        public void InitaliseHandshakeHash(bool legacy)
        {
            if (legacy)
            {
                _VerifyHandshakeSHA1 = new Org.BouncyCastle.Crypto.Digests.Sha1Digest();
                _VerifyHandshakeMD5 = new Org.BouncyCastle.Crypto.Digests.MD5Digest();
            }
            else
                _VerifyHandshake = new Org.BouncyCastle.Crypto.Digests.Sha256Digest();
        }

        public void UpdateHandshakeHash(byte[] data)
        {
            if (_VerifyHandshake == null)
            {
                if (_VerifyHandshakeSHA1 != null)
                { 
                    _VerifyHandshakeSHA1.BlockUpdate(data, 0, data.Length);
                    _VerifyHandshakeMD5.BlockUpdate(data, 0, data.Length);
                }
            }
            else
                _VerifyHandshake.BlockUpdate(data, 0, data.Length);
        }

        public byte[] GetHash()
        {
            byte[] handshakeHash;
            if (_VerifyHandshake == null)
            {
                IDigest sha1 = new Org.BouncyCastle.Crypto.Digests.Sha1Digest(_VerifyHandshakeSHA1);
                IDigest md5 = new Org.BouncyCastle.Crypto.Digests.MD5Digest(_VerifyHandshakeMD5);
                handshakeHash = new byte[sha1.GetDigestSize() + md5.GetDigestSize()];
                md5.DoFinal(handshakeHash, 0);
                sha1.DoFinal(handshakeHash, md5.GetDigestSize());
            }
            else
            {
                IDigest hash = new Org.BouncyCastle.Crypto.Digests.Sha256Digest((Org.BouncyCastle.Crypto.Digests.Sha256Digest)_VerifyHandshake);
                handshakeHash = new byte[hash.GetDigestSize()];
                hash.DoFinal(handshakeHash, 0);
            }
            return handshakeHash;
        }
    }
}
