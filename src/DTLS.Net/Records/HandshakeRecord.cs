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

using System.IO;

namespace DTLS
{
    //struct {
    //     HandshakeType msg_type;
    //     uint24 length;
    //     uint16 message_seq;                               // New field
    //     uint24 fragment_offset;                           // New field
    //     uint24 fragment_length;                           // New field
    //     select (HandshakeType) {
    //       case hello_request: HelloRequest;
    //       case client_hello:  ClientHello;
    //       case server_hello:  ServerHello;
    //       case hello_verify_request: HelloVerifyRequest;  // New field
    //       case certificate:Certificate;
    //       case server_key_exchange: ServerKeyExchange;
    //       case certificate_request: CertificateRequest;
    //       case server_hello_done:ServerHelloDone;
    //       case certificate_verify:  CertificateVerify;
    //       case client_key_exchange: ClientKeyExchange;
    //       case finished: Finished;
    //     } body; } Handshake;

    internal class HandshakeRecord
	{
		public const int RECORD_OVERHEAD = 12;

        public THandshakeType MessageType { get; set; }

        public uint Length { get; set; }

        public ushort MessageSeq { get; set; }

        public uint FragmentOffset { get; set; }

        public uint FragmentLength { get; set; }


        public static HandshakeRecord Deserialise(Stream stream)
		{
            var result = new HandshakeRecord
            {
                MessageType = (THandshakeType)stream.ReadByte(),
                Length = NetworkByteOrderConverter.ToUInt24(stream),
                MessageSeq = NetworkByteOrderConverter.ToUInt16(stream),
                FragmentOffset = NetworkByteOrderConverter.ToUInt24(stream),
                FragmentLength = NetworkByteOrderConverter.ToUInt24(stream)
            };
            return result;
		}

		public void Serialise(Stream stream)
		{
			stream.WriteByte((byte)this.MessageType);
			NetworkByteOrderConverter.WriteUInt24(stream, this.Length);
			NetworkByteOrderConverter.WriteUInt16(stream, this.MessageSeq);
			NetworkByteOrderConverter.WriteUInt24(stream, this.FragmentOffset);
			NetworkByteOrderConverter.WriteUInt24(stream, this.FragmentLength);
		}
	}



//   struct {
//     ProtocolVersion server_version;
//     opaque cookie<0..2^8-1>; } HelloVerifyRequest;
}
