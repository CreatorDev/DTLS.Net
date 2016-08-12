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
	internal static class NetworkByteOrderConverter
	{
		public static short ToInt16(Stream stream)
		{
			short result = 0;
			byte[] buffer = new byte[2];
			int read = stream.Read(buffer, 0, 2);
			if (read == 2)
				result = ToInt16(buffer, 0);
			else
				throw new EndOfStreamException();
			return result;
		}

		public static short ToInt16(byte[] value, uint startIndex)
		{
			short result;
			result = (short)((int)(value[startIndex]) << 8 | (int)value[startIndex + 1]);
			return result;
		}

		public static int ToInt24(Stream stream)
		{
			int result = 0;
			byte[] buffer = new byte[3];
			int read = stream.Read(buffer, 0, 3);
			if (read == 3)
				result = ToInt24(buffer, 0);
			else
				throw new EndOfStreamException();
			return result;
		}

		public static int ToInt24(byte[] value, uint startIndex)
		{
			int result;
			result = (((int)value[startIndex]) << 16 | ((int)value[startIndex + 1]) << 8 | (int)value[startIndex + 2]);
			return result;
		}

		public static int ToInt32(Stream stream)
		{
			int result = 0;
			byte[] buffer = new byte[4];
			int read = stream.Read(buffer, 0, 4);
			if (read == 4)
				result = ToInt32(buffer, 0);
			else
				throw new EndOfStreamException();
			return result;
		}

		public static int ToInt32(byte[] value, uint startIndex)
		{
			int result;
			result = (((int)value[startIndex]) << 24 | ((int)value[startIndex + 1]) << 16 | ((int)value[startIndex + 2]) << 8 | (int)value[startIndex + 3]);
			return result;
		}

		public static long ToInt48(Stream stream)
		{
			long result = 0;
			byte[] buffer = new byte[6];
			int read = stream.Read(buffer, 0, 6);
			if (read == 6)
				result = ToInt48(buffer, 0);
			else
				throw new EndOfStreamException();
			return result;
		}

		public static long ToInt48(byte[] value, uint startIndex)
		{
			long result;
			result = ToUInt32(value, startIndex + 2);
			result = result | (((long)ToUInt16(value, startIndex)) << 32);
			return result;
		}


		public static ushort ToUInt16(Stream stream)
		{
			ushort result = 0;
			byte[] buffer = new byte[2];
			int read = stream.Read(buffer, 0, 2);
			if (read == 2)
				result = ToUInt16(buffer, 0);
			else
				throw new EndOfStreamException();
			return result;
		}

		public static ushort ToUInt16(byte[] value, uint startIndex)
		{
			ushort result;
			result = (ushort)((uint)(value[startIndex]) << 8 | (uint)value[startIndex + 1]);
			return result;
		}

		public static uint ToUInt24(Stream stream)
		{
			uint result = 0;
			byte[] buffer = new byte[3];
			int read = stream.Read(buffer, 0, 3);
			if (read == 3)
				result = ToUInt24(buffer, 0);
			else
				throw new EndOfStreamException();
			return result;
		}

		public static uint ToUInt24(byte[] value, uint startIndex)
		{
			uint result;
			result = (((uint)value[startIndex]) << 16 | ((uint)value[startIndex + 1]) << 8 | (uint)value[startIndex + 2]);
			return result;
		}

		public static uint ToUInt32(Stream stream)
		{
			uint result = 0;
			byte[] buffer = new byte[4];
			int read = stream.Read(buffer, 0, 4);
			if (read == 4)
				result = ToUInt32(buffer, 0);
			else
				throw new EndOfStreamException();
			return result;
		}

		public static uint ToUInt32(byte[] value, uint startIndex)
		{
			uint result;
			result = (((uint)value[startIndex]) << 24 | ((uint)value[startIndex + 1]) << 16 | ((uint)value[startIndex + 2]) << 8 | (uint)value[startIndex + 3]);
			return result;
		}

		public static ulong ToUInt48(Stream stream)
		{
			ulong result = 0;
			byte[] buffer = new byte[6];
			int read = stream.Read(buffer, 0, 6);
			if (read == 6)
				result = ToUInt48(buffer, 0);
			else
				throw new EndOfStreamException();
			return result;
		}

		public static ulong ToUInt48(byte[] value, uint startIndex)
		{
			ulong result;
			result = ToUInt32(value, startIndex + 2);
			result = result | (((ulong)ToUInt16(value,startIndex)) << 32);
			return result;
		}


		public static void WriteInt16(Stream stream, short value)
		{
			byte[] buffer = new byte[4];
			buffer[0] = (byte)(value >> 8);
			buffer[1] = (byte)(value & 0xFF);
			stream.Write(buffer, 0, 2);
		}

		public static void WriteInt24(Stream stream, int value)
		{
			byte[] buffer = new byte[3];
			buffer[0] = (byte)(value >> 16);
			buffer[1] = (byte)(value >> 8);
			buffer[2] = (byte)(value & 0xFF);
			stream.Write(buffer, 0, 3);
		}

		public static void WriteInt32(Stream stream, int value)
		{
			byte[] buffer = new byte[4];
			buffer[0] = (byte)(value >> 24);
			buffer[1] = (byte)(value >> 16);
			buffer[2] = (byte)(value >> 8);
			buffer[3] = (byte)(value & 0xFF);
			stream.Write(buffer, 0, 4);
		}

		public static void WriteInt32(byte[] buffer, int startIndex, int value)
		{
			buffer[startIndex] = (byte)(value >> 24);
			buffer[startIndex + 1] = (byte)(value >> 16);
			buffer[startIndex + 2] = (byte)(value >> 8);
			buffer[startIndex + 3] = (byte)(value & 0xFF);
		}

		public static void WriteInt48(Stream stream, long value)
		{
			byte[] buffer = new byte[6];
			buffer[0] = (byte)(value >> 40);
			buffer[1] = (byte)(value >> 32);
			buffer[2] = (byte)(value >> 24);
			buffer[3] = (byte)(value >> 16);
			buffer[4] = (byte)(value >> 8);
			buffer[5] = (byte)(value & 0xFF);
			stream.Write(buffer, 0, 6);
		}
		
		public static void WriteUInt16(Stream stream, ushort value)
		{
			byte[] buffer = new byte[4];
			buffer[0]= (byte)(value >> 8);
			buffer[1] = (byte)(value & 0xFF);
			stream.Write(buffer, 0, 2);
		}

		public static void WriteUInt24(Stream stream, uint value)
		{
			byte[] buffer = new byte[3];
			buffer[0] = (byte)(value >> 16);
			buffer[1] = (byte)(value >> 8);
			buffer[2] = (byte)(value & 0xFF);
			stream.Write(buffer, 0, 3);
		}

		public static void WriteUInt32(Stream stream, uint value)
		{
			byte[] buffer = new byte[4];
			buffer[0]= (byte)(value >> 24);
			buffer[1]= (byte)(value >> 16);
			buffer[2]= (byte)(value >> 8);
			buffer[3]= (byte)(value & 0xFF);
			stream.Write(buffer, 0, 4);
		}

        public static void WriteUInt16(byte[] buffer, int startIndex, ushort value)
        {
            buffer[startIndex] = (byte)(value >> 8);
            buffer[startIndex+ 1] = (byte)(value & 0xFF);
        }

		public static void WriteUInt32(byte[] buffer, int startIndex, uint value)
		{
			buffer[startIndex] = (byte)(value >> 24);
			buffer[startIndex + 1] = (byte)(value >> 16);
			buffer[startIndex + 2] = (byte)(value >> 8);
			buffer[startIndex + 3] = (byte)(value & 0xFF);
		}

		public static void WriteUInt48(Stream stream, ulong value)
		{
			byte[] buffer = new byte[6];
			buffer[0] = (byte)(value >> 40);
			buffer[1] = (byte)(value >> 32);
			buffer[2] = (byte)(value >> 24);
			buffer[3] = (byte)(value >> 16);
			buffer[4] = (byte)(value >> 8);
			buffer[5] = (byte)(value & 0xFF);
			stream.Write(buffer, 0, 6);
		}


	}

}
