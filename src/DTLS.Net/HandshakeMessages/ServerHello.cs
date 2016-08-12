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

		Version _ServerVersion;
		RandomData _Random;
		byte[] _SessionID;
		ushort _CipherSuite;
		byte _CompressionMethod;
		Extensions _Extensions;
		
		public THandshakeType MessageType { get { return THandshakeType.ServerHello; } }


		public Version ServerVersion
		{
			get { return _ServerVersion; }
			set { _ServerVersion = value; }
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

		public ushort CipherSuite
		{
			get { return _CipherSuite; }
			set { _CipherSuite = value; }
		}

		public byte CompressionMethod
		{
			get { return _CompressionMethod; }
			set { _CompressionMethod = value; }
		}

		public Extensions Extensions
		{
			get { return _Extensions; }
			set { _Extensions = value; }
		}

		public ServerHello()
		{
			_ServerVersion = DefaultVersion;
		}

		public void AddExtension(IExtension extension)
		{
			if (_Extensions == null)
			{
				_Extensions = new Extensions();
			}
			Extension item = new Extension();
			item.ExtensionType = extension.ExtensionType;
			item.SpecifcExtension = extension;
			_Extensions.Add(item);
		}

		public int CalculateSize(Version version)
		{
			int result = 38; //Version + Length of cookie
			if (_SessionID != null)
				result += _SessionID.Length;
			if (_Extensions != null)
				result += _Extensions.CalculateSize();
			return result;
		}

		public static ServerHello Deserialise(Stream stream)
		{
			ServerHello result = new ServerHello();
			result._ServerVersion = new Version(255 - stream.ReadByte(), 255 - stream.ReadByte());
			result._Random = RandomData.Deserialise(stream);
			int length = stream.ReadByte();
			if (length > 0)
			{
				result._SessionID = new byte[length];
				stream.Read(result._SessionID, 0, length);
			}
			result._CipherSuite = NetworkByteOrderConverter.ToUInt16(stream);
			result._CompressionMethod = (byte)stream.ReadByte();
			result._Extensions = Extensions.Deserialise(stream, false);
			return result;
		}

		public void Serialise(System.IO.Stream stream, Version version)
		{
			stream.WriteByte((byte)(255 - _ServerVersion.Major));
			stream.WriteByte((byte)(255 - _ServerVersion.Minor));
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
			NetworkByteOrderConverter.WriteUInt16(stream, _CipherSuite);
			stream.WriteByte(_CompressionMethod);
			if (_Extensions != null)
				_Extensions.Serialise(stream);
		}


	}
}
