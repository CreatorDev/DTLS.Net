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
using System.Net;
using System.Security.Cryptography;

namespace DTLS
{

    //opaque SessionID<0..32>;

    //      uint8 CipherSuite[2];    /* Cryptographic suite selector */

    //      enum { null(0), (255) } CompressionMethod;


    //    struct {
    //    ExtensionType extension_type;
    //    opaque extension_data<0..2^16-1>;
    //} Extension;

    //enum {
    //    signature_algorithms(13), (65535)
    //} ExtensionType;

    //  struct {
    //ProtocolVersion client_version;
    //Random random;
    //SessionID session_id;
    //opaque cookie<0..2^8-1>;                             // New field
    //CipherSuite cipher_suites<2..2^16-1>;
    //CompressionMethod compression_methods<1..2^8-1>; 
    //      select (extensions_present) {
    //          case false:
    //              struct {};
    //          case true:
    //              Extension extensions<0..2^16-1>;
    //      };
    //} ClientHello;
    internal class ClientHello: IHandshakeMessage
	{
        public THandshakeType MessageType => THandshakeType.ClientHello;

        public Version ClientVersion { get; set; }

        public RandomData Random { get; set; }
        
        public byte[] SessionID { get; set; }
        
        public byte[] Cookie { get; set; }

        public ushort[] CipherSuites { get; set; }

        public byte[] CompressionMethods { get; set; }

        public Extensions Extensions { get; set; }
        
        public int CalculateSize(Version version)
        {
            var result = 39;  // Version (2 bytes) + Random (32 bytes) + SessionIDLength (1 byte) + _CompressionMethodsLength (1 byte) 
                              // + CookieLength (1 byte) + CipherSuitesLength (2 bytes) 
            if (this.SessionID != null)
            {
                result += this.SessionID.Length;
            }

            if (this.Cookie != null)
            {
                result += this.Cookie.Length;
            }

            if (this.CipherSuites != null)
            {
                result += (this.CipherSuites.Length * 2);
            }

            if (this.CompressionMethods != null)
            {
                result += this.CompressionMethods.Length;
            }

            if (this.Extensions == null)
            {
                result += 2;
            }
            else
            {
                result += this.Extensions.CalculateSize();
            }

            return result;
        }

		public byte[] CalculateCookie(EndPoint remoteEndPoint, byte[] secret)
		{
            if (remoteEndPoint == null)
            {
                throw new ArgumentNullException(nameof(remoteEndPoint));
            }

            if (secret == null)
            {
                throw new ArgumentNullException(nameof(secret));
            }

            //Cookie = HMAC(Secret, Client-IP, Client-Parameters)
            //(version, random, session_id, cipher_suites,  compression_method) 
            var result = new byte[32];
			var socketAddress = remoteEndPoint.Serialize();
			var socketAddressSize = socketAddress.Size;
			var message = new byte[socketAddressSize + 34];
			for (var index = 0; index < socketAddressSize; index++)
			{
				message[0] = socketAddress[index];
			}
			NetworkByteOrderConverter.WriteUInt32(message, socketAddressSize, this.Random.UnixTime);
			Buffer.BlockCopy(this.Random.RandomBytes, 0, message, socketAddressSize + 4, 28);
			var hmac = new HMACSHA256(secret);
			var hash = hmac.ComputeHash(message);
			Buffer.BlockCopy(hash, 0, result, 0, 32);
			return result;
		}

		public static ClientHello Deserialise(Stream stream)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            var result = new ClientHello
            {
                ClientVersion = new Version(255 - stream.ReadByte(), 255 - stream.ReadByte()),
                Random = RandomData.Deserialise(stream)
            };

            var length = stream.ReadByte();
			if (length > 0)
			{
				result.SessionID = new byte[length];
				stream.Read(result.SessionID, 0, length);
			}

			length = stream.ReadByte();
			if (length > 0)
			{
				result.Cookie = new byte[length];
				stream.Read(result.Cookie, 0, length);
			}

			var cipherSuitesLength = (ushort)(NetworkByteOrderConverter.ToUInt16(stream) / 2);
			if (cipherSuitesLength > 0)
			{
				result.CipherSuites = new ushort[cipherSuitesLength];
				for (uint index = 0; index < cipherSuitesLength; index++)
				{
					result.CipherSuites[index] = NetworkByteOrderConverter.ToUInt16(stream);
				}
			}

			length = stream.ReadByte();
			if (length > 0)
			{
				result.CompressionMethods = new byte[length];
				stream.Read(result.CompressionMethods, 0, length);
			}

			result.Extensions = Extensions.Deserialise(stream, true);
			return result;
		}

		public void Serialise(Stream stream, Version version)
		{
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            stream.WriteByte((byte)(255 - this.ClientVersion.Major));
			stream.WriteByte((byte)(255 - this.ClientVersion.Minor));
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

			if (this.Cookie == null)
			{
				stream.WriteByte(0);
			}
			else
			{
				stream.WriteByte((byte)this.Cookie.Length);
                stream.Write(this.Cookie, 0, this.Cookie.Length);
			}

			if (this.CipherSuites.Length > 0)
			{
				NetworkByteOrderConverter.WriteUInt16(stream,(ushort)(this.CipherSuites.Length * 2));
				for (var index = 0; index < this.CipherSuites.Length; index++)
				{
					NetworkByteOrderConverter.WriteUInt16(stream, this.CipherSuites[index]);
				}
			}

			stream.WriteByte((byte)this.CompressionMethods.Length);
			stream.Write(this.CompressionMethods, 0, this.CompressionMethods.Length);

			if (this.Extensions == null)
            {
                NetworkByteOrderConverter.WriteUInt16(stream, 0);
            }
            else
            {
                this.Extensions.Serialise(stream);
			}
		}
	}
}