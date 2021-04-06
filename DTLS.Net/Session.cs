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

using Org.BouncyCastle.Crypto.Tls;
using System;
using System.Net;

namespace DTLS
{
    internal class Session
    {
        
        private long _SequenceNumber; //realy only 48 bit

        public Guid SessionID { get; set; }

        public EndPoint RemoteEndPoint { get; set; }

        public ushort Epoch { get; set; }

        public Version Version { get; set; }

        public TlsCipher Cipher { get; set; }

        public ushort ClientEpoch { get; set; }

        public long ClientSequenceNumber { get; set; }

        public ushort? EncyptedClientEpoch { get; set; }

        internal HandshakeInfo Handshake { get; set; }
        
        public DTLSRecords Records { get; private set; }

        public string PSKIdentity { get; set; }        

        public CertificateInfo CertificateInfo { get; set; }

        public Session()
        {
            this.Handshake = new HandshakeInfo();
            this.Records = new DTLSRecords();
        }


        public void ChangeEpoch()
        {
            this.Epoch++;
            this._SequenceNumber = 0;
        }

        public long NextSequenceNumber()
        {
            var result = this._SequenceNumber++;
            return result;
        }


        internal bool IsEncypted(DTLSRecord record)
        {
            var result = false;
            if (this.EncyptedClientEpoch.HasValue)
            {
                result = record.Epoch == this.EncyptedClientEpoch.Value;
            }

            return result;
        }

        internal void Reset()
        {
            this.Epoch = 0;
            this._SequenceNumber = 0;
            this.Cipher = null;
            this.ClientEpoch = 0;
            this.ClientSequenceNumber = 0;
            this.EncyptedClientEpoch = null;
            this.PSKIdentity = null;
            this.CertificateInfo = null;
            this.Records.Clear();
            this.Handshake = new HandshakeInfo();
        }

        internal void SetEncyptChange(DTLSRecord record) => this.EncyptedClientEpoch = (ushort)(record.Epoch + 1);
    }
}
