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

    //    struct {
    //    ProtocolVersion server_version;
    //    Random random;
    //    SessionID session_id;
    //    CipherSuite cipher_suite;
    //    CompressionMethod compression_method;
    //    select (extensions_present) {
    //        case false:
    //            struct {};
    //        case true:
    //            Extension extensions<0..2^16-1>;
    //    };
    //} ServerHello;

    internal class ServerHello : IHandshakeMessage
	{
		public static Version DefaultVersion = new Version(1, 0);

        public THandshakeType MessageType => THandshakeType.ServerHello;

        public Version ServerVersion { get; set; }

        public RandomData Random { get; set; }

        public byte[] SessionID { get; set; }

        public ushort CipherSuite { get; set; }

        public byte CompressionMethod { get; set; }

        public Extensions Extensions { get; set; }

        public ServerHello() => this.ServerVersion = DefaultVersion;

        public void AddExtension(IExtension extension)
		{
            if (extension == null)
            {
                throw new ArgumentNullException(nameof(extension));
            }

            if (this.Extensions == null)
			{
                this.Extensions = new Extensions();
			}

            var item = new Extension
            {
                ExtensionType = extension.ExtensionType,
                SpecificExtension = extension
            };

            this.Extensions.Add(item);
		}

		public int CalculateSize(Version version)
		{
            var result = 38; //Version + Length of cookie
			if (this.SessionID != null)
            {
                result += this.SessionID.Length;
            }

            if (this.Extensions != null)
            {
                result += this.Extensions.CalculateSize();
            }

            return result;
		}

		public static ServerHello Deserialise(Stream stream)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            var result = new ServerHello
            {
                ServerVersion = new Version(255 - stream.ReadByte(), 255 - stream.ReadByte()),
                Random = RandomData.Deserialise(stream)
            };

            var length = stream.ReadByte();
			if (length > 0)
			{
				result.SessionID = new byte[length];
				stream.Read(result.SessionID, 0, length);
			}

			result.CipherSuite = NetworkByteOrderConverter.ToUInt16(stream);
			result.CompressionMethod = (byte)stream.ReadByte();
			result.Extensions = Extensions.Deserialise(stream, false);
			return result;
		}

		public void Serialise(Stream stream, Version version)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }
            
            stream.WriteByte((byte)(255 - this.ServerVersion.Major));
			stream.WriteByte((byte)(255 - this.ServerVersion.Minor));
            this.Random.Serialise(stream);

			if (this.SessionID == null)
			{
				stream.WriteByte(0);
			}
			else
			{
				stream.WriteByte((byte)this.SessionID.Length);
				stream.Write(this.SessionID, 0, this.SessionID.Length);
			}

			NetworkByteOrderConverter.WriteUInt16(stream, this.CipherSuite);
			stream.WriteByte(this.CompressionMethod);
			if (this.Extensions != null)
            {
                this.Extensions.Serialise(stream);
            }
        }
	}
}