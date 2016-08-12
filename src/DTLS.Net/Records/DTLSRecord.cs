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

	//RFC 6347 DTLS1.2
	// RFC 4347 DTLS
	//RFC 5246 TLS1.2
	internal class DTLSRecord
	{
		public static Version DefaultVersion = new Version(1, 0);
        public static Version Version1_0 = new Version(1, 0);
        public static Version Version1_2 = new Version(1, 2);

		public const int RECORD_OVERHEAD = 13;

		TRecordType _RecordType;
		Version _Version;
		ushort _Epoch;
		long _SequenceNumber; //realy only 48 bit
		ushort _Length;
		byte[] _Fragment;
		EndPoint _RemoteEndPoint;

		 //             struct {
		 //  ContentType type;
		 //  ProtocolVersion version;
		 //  uint16 epoch;                                    // New field
		 //  uint48 sequence_number;                          // New field
		 //  uint16 length;
		 //  opaque fragment[DTLSPlaintext.length];
		 //} DTLSPlaintext;

		public TRecordType RecordType 
		{
			get { return _RecordType; }
			set { _RecordType = value; }
		}

		public Version Version
		{
			get { return _Version; }
			set { _Version = value; }
		}

		public ushort Epoch
		{
			get { return _Epoch; }
			set { _Epoch = value; }
		}

		public long SequenceNumber
		{
			get { return _SequenceNumber; }
			set { _SequenceNumber = value; }
		}

		public byte[] Fragment
		{
			get { return _Fragment; }
			set 
			{
				_Fragment = value;
				if (_Fragment != null)
					_Length = (ushort)_Fragment.Length;
			}
		}

		public EndPoint RemoteEndPoint
		{
			get { return _RemoteEndPoint; }
			set { _RemoteEndPoint = value; }
		}

		public DTLSRecord()
		{
			_Version = DefaultVersion;
		}

		public static DTLSRecord Deserialise(Stream stream)
		{
			DTLSRecord result = new DTLSRecord();
			result._RecordType = (TRecordType)stream.ReadByte();
			result._Version = new Version(255 - stream.ReadByte(), 255 - stream.ReadByte());
			result._Epoch = NetworkByteOrderConverter.ToUInt16(stream);
			result._SequenceNumber = NetworkByteOrderConverter.ToInt48(stream);
			result._Length = NetworkByteOrderConverter.ToUInt16(stream);
			if (result._Length > 0)
			{
				result._Fragment = new byte[result._Length];
				int length = stream.Read(result._Fragment, 0, result._Length);
                while (length < result._Length)
                {
                    length += stream.Read(result._Fragment, length, result._Length - length);
                }
			}
			return result;
		}


		public void Serialise(Stream stream)
		{
			stream.WriteByte((byte)_RecordType);
			stream.WriteByte((byte)(255 - _Version.Major));
			stream.WriteByte((byte)(255 - _Version.Minor));
			NetworkByteOrderConverter.WriteUInt16(stream, _Epoch);
			NetworkByteOrderConverter.WriteInt48(stream, _SequenceNumber);
			NetworkByteOrderConverter.WriteUInt16(stream, _Length);
			if (_Length > 0)
			{
				stream.Write(_Fragment, 0, _Length);
			}
		}
	}
}
