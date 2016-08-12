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
using System.IO;
using System.Net;

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
		private Version _ClientVersion;
		private RandomData _Random;
		private byte[] _SessionID;
		private byte[] _Cookie;
		private ushort[] _CipherSuites;
		private byte[] _CompressionMethods;
		private Extensions _Extensions;

        public THandshakeType MessageType { get { return THandshakeType.ClientHello; } }
        
		public Version ClientVersion
		{
			get { return _ClientVersion; }
			set { _ClientVersion = value; }
		}

		public RandomData Random
		{
			get { return _Random; }
			set { _Random = value; }
		}


		public byte[] SessionID
		{
			get { return _SessionID; }
			set { _SessionID = value; }
		}


		public byte[] Cookie
		{
			get { return _Cookie; }
			set { _Cookie = value; }
		}

		public ushort[] CipherSuites
		{
			get { return _CipherSuites; }
			set { _CipherSuites = value; }
		}

		public byte[] CompressionMethods
		{
			get { return _CompressionMethods; }
			set { _CompressionMethods = value; }
		}

		public Extensions Extensions
		{
			get { return _Extensions; }
			set { _Extensions = value; }
		}


        public int CalculateSize(Version version)
        {
            int result = 39;  // Version (2 bytes) + Random (32 bytes) + SessionIDLength (1 byte) + _CompressionMethodsLength (1 byte) 
                              // + CookieLength (1 byte) + CipherSuitesLength (2 bytes) 
            if (_SessionID != null)
                result += _SessionID.Length;
            if (_Cookie != null)
                result += Cookie.Length;
            if (_CipherSuites != null)
                result += (_CipherSuites.Length * 2);
            if (_CompressionMethods != null)
                result += _CompressionMethods.Length;
            if (_Extensions == null)
                result += 2;
            else
                result += _Extensions.CalculateSize();
            return result;
        }

		public byte[] CalculateCookie(EndPoint remoteEndPoint, byte[] secret)
		{
			//Cookie = HMAC(Secret, Client-IP, Client-Parameters)
			//(version, random, session_id, cipher_suites,  compression_method) 
			byte[] result = new byte[32];
			SocketAddress socketAddress = remoteEndPoint.Serialize();
			int socketAddressSize = socketAddress.Size;
			byte[] message = new byte[socketAddressSize + 34];
			for (int index = 0; index < socketAddressSize; index++)
			{
				message[0] = socketAddress[index];
			}
			NetworkByteOrderConverter.WriteUInt32(message, socketAddressSize, _Random.UnixTime);
			Buffer.BlockCopy(_Random.RandomBytes, 0, message, socketAddressSize + 4, 28);
			System.Security.Cryptography.HMACSHA256 hmac = new System.Security.Cryptography.HMACSHA256(secret);
			byte[] hash = hmac.ComputeHash(message);
			Buffer.BlockCopy(hash, 0, result, 0, 32);
			return result;
		}

		public static ClientHello Deserialise(Stream stream)
		{
			ClientHello result = new ClientHello();
			result._ClientVersion = new Version(255 - stream.ReadByte(), 255 - stream.ReadByte());
			result._Random = RandomData.Deserialise(stream);
			int length = stream.ReadByte();
			if (length > 0)
			{
				result._SessionID = new byte[length];
				stream.Read(result._SessionID, 0, length);
			}
			length = stream.ReadByte();
			if (length > 0)
			{
				result._Cookie = new byte[length];
				stream.Read(result._Cookie, 0, length);
			}
			ushort cipherSuitesLength = (ushort)(NetworkByteOrderConverter.ToUInt16(stream) / 2);
			if (cipherSuitesLength > 0)
			{
				result._CipherSuites = new ushort[cipherSuitesLength];
				for (uint index = 0; index < cipherSuitesLength; index++)
				{
					result._CipherSuites[index] = NetworkByteOrderConverter.ToUInt16(stream);
				}
			}
			length = stream.ReadByte();
			if (length > 0)
			{
				result._CompressionMethods = new byte[length];
				stream.Read(result._CompressionMethods, 0, length);
			}
			result._Extensions = Extensions.Deserialise(stream, true);
			return result;
		}

		public void Serialise(System.IO.Stream stream, Version version)
		{
			stream.WriteByte((byte)(255 - _ClientVersion.Major));
			stream.WriteByte((byte)(255 - _ClientVersion.Minor));
			_Random.Serialise(stream);
			if (_SessionID == null)
			{
				stream.WriteByte(0);	
			}
			else
			{
				stream.WriteByte((byte)_SessionID.Length);
				stream.Write(_SessionID, 0, _SessionID.Length);	
			}
			if (_Cookie == null)
			{
				stream.WriteByte(0);
			}
			else
			{
				stream.WriteByte((byte)_Cookie.Length);
                stream.Write(_Cookie, 0, _Cookie.Length);
			}
			if (_CipherSuites.Length > 0)
			{
				NetworkByteOrderConverter.WriteUInt16(stream,(ushort)(_CipherSuites.Length * 2));
				for (uint index = 0; index < _CipherSuites.Length; index++)
				{
					NetworkByteOrderConverter.WriteUInt16(stream,_CipherSuites[index]);
				}
			}
			stream.WriteByte((byte)_CompressionMethods.Length);
			stream.Write(_CompressionMethods, 0, _CompressionMethods.Length);
			if (_Extensions == null)
                NetworkByteOrderConverter.WriteUInt16(stream, 0);
            else
            {
				_Extensions.Serialise(stream);
			}

		}

	}
}
