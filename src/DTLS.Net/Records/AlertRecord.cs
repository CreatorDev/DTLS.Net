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

     //enum { warning(1), fatal(2), (255) } AlertLevel;

     // enum {
     //     close_notify(0),
     //     unexpected_message(10),
     //     bad_record_mac(20),
     //     decryption_failed_RESERVED(21),
     //     record_overflow(22),
     //     decompression_failure(30),
     //     handshake_failure(40),
     //     no_certificate_RESERVED(41),
     //     bad_certificate(42),
     //     unsupported_certificate(43),
     //     certificate_revoked(44),
     //     certificate_expired(45),
     //     certificate_unknown(46),
     //     illegal_parameter(47),
     //     unknown_ca(48),
     //     access_denied(49),
     //     decode_error(50),
     //     decrypt_error(51),
     //     export_restriction_RESERVED(60),
     //     protocol_version(70),
     //     insufficient_security(71),
     //     internal_error(80),
     //     user_canceled(90),
     //     no_renegotiation(100),
     //     unsupported_extension(110),
     //     (255)
     // } AlertDescription;

     // struct {
     //     AlertLevel level;
     //     AlertDescription description;
     // } Alert;

    internal class AlertRecord
    {
        private TAlertLevel _AlertLevel;
        private TAlertDescription _AlertDescription;

        public TAlertLevel AlertLevel
        {
            get { return _AlertLevel; }
            set { _AlertLevel = value; }
        }

        public TAlertDescription AlertDescription
        {
            get { return _AlertDescription; }
            set { _AlertDescription = value; }
        }

        public static AlertRecord Deserialise(byte[] data)
        {
            AlertRecord result = new AlertRecord();
            result._AlertLevel = (TAlertLevel)data[0];
            result._AlertDescription = (TAlertDescription)data[1];
            return result;
        }

        public static AlertRecord Deserialise(System.IO.Stream stream)
        {
            AlertRecord result = new AlertRecord();
            result._AlertLevel = (TAlertLevel)stream.ReadByte();
            result._AlertDescription = (TAlertDescription)stream.ReadByte();
            return result;
        }

        public void Serialise(System.IO.Stream stream)
        {
            stream.WriteByte((byte)_AlertLevel);
            stream.WriteByte((byte)_AlertDescription);
        }
    }
}
