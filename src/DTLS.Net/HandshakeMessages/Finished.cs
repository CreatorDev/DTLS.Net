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
	
	  //struct {
	  //    opaque verify_data[verify_data_length];
	  //} Finished;

	  //verify_data
	  //   PRF(master_secret, finished_label, Hash(handshake_messages))
	  //      [0..verify_data_length-1];

	  //finished_label
	  //   For Finished messages sent by the client, the string
	  //   "client finished".  For Finished messages sent by the server,
	  //   the string "server finished".

	 //verify_data_length default = 12

	internal class Finished : IHandshakeMessage
	{
		private byte[] _VerifyData;

		public THandshakeType MessageType
		{
			get { return THandshakeType.Finished; }
		}

        public byte[] VerifyData { get { return _VerifyData; } set { _VerifyData = value;} }

		public int CalculateSize(Version version)
		{
            return 12;
		}
        
		public static Finished Deserialise(Stream stream)
		{
			Finished result = new Finished();
			result._VerifyData = new byte[12];
			stream.Read(result._VerifyData, 0, 12);
			return result;
		}

		public void Serialise(Stream stream, Version version)
		{
            stream.Write(_VerifyData, 0, _VerifyData.Length);
		}
	}
}
