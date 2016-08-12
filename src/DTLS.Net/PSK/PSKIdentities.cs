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
using System.Text;
using System.Xml;
using System.IO;

namespace DTLS
{
    public class PSKIdentities: IEqualityComparer<byte[]>
    {
        private Dictionary<byte[], PSKIdentity> _Identities;

        public int Count { get {return _Identities.Count;} }

        public PSKIdentities()
        {
            _Identities = new Dictionary<byte[], PSKIdentity>(10,this);
        }

        public void AddIdentity(byte[] identity, byte[] key)
        {
            PSKIdentity pskIdentity = new PSKIdentity() { Identity = identity, Key = key };
            _Identities.Add(pskIdentity.Identity, pskIdentity);
        }
        
        public void AddIdentity(string identity, byte[] key)
        {
            PSKIdentity pskIdentity = new PSKIdentity() { Identity = Encoding.UTF8.GetBytes(identity), Key = key };
            _Identities.Add(pskIdentity.Identity, pskIdentity);
        }

        public byte[] GetKey(byte[] identity)
        {
            byte[] result = null;
            PSKIdentity pskIdentity;
            if (_Identities.TryGetValue(identity, out pskIdentity))
            {
                result = pskIdentity.Key;
            }
            return result;
        }

        internal PSKIdentity GetRandom()
        {
            PSKIdentity result = null;
            if (_Identities.Count > 0)
            {
                Random random = new Random();
                int index = random.Next(_Identities.Count);
                int count = 0;
                foreach (byte[] identity in _Identities.Keys)
                {
                    if (count == index)
                    {
                        _Identities.TryGetValue(identity, out result);
                        break;
                    }
                    count++;
                }
            }
            return result;
        }

        private static byte[] HexToBytes(string hex)
        {
            byte[] result = new byte[hex.Length / 2];
            int count = 0;
            for (int index = 0; index < hex.Length; index += 2)
            {
                result[count] = Convert.ToByte(hex.Substring(index, 2), 16);
                count++;
            }
            return result;
        }

        public void LoadFromFile(string fileName)
        {
            if (File.Exists(fileName))
            {
                using (XmlReader reader = XmlReader.Create(fileName))
                {
                    while (reader.Read())
                    {
                        if ((reader.NodeType == XmlNodeType.Element) && (reader.Name == "Identity"))
                        {
                            if (reader.HasAttributes)
                            {
                                string name = null;
                                byte[] key = null;
                                reader.MoveToFirstAttribute();
                                do
                                {
                                    if (reader.Name == "name")
                                        name = reader.Value;
                                    else if (reader.Name == "key")
                                        key = HexToBytes(reader.Value);
                                } while (reader.MoveToNextAttribute());
                                reader.MoveToElement();
                                if ((name != null) && (key != null))
                                    AddIdentity(name, key);
                            }
                        }
                    }
                }
            }
        }

        bool IEqualityComparer<byte[]>.Equals(byte[] x, byte[] y)
        {
            return TLSUtils.ByteArrayCompare(x, y);
        }

        int IEqualityComparer<byte[]>.GetHashCode(byte[] obj)
        {
            int result = 0;
            for (int i = 0; i < obj.Length; i++)
            {
                switch (i % 4)
                {
                    case 0:
                        result = result | obj[i];
                        break;
                    case 1:
                        result = result | (obj[i] << 8);
                        break;
                    case 2:
                        result = result | (obj[i] << 16);
                        break;
                    case 3:
                        result = result | (obj[i] << 24);
                        break;
                    default:
                        break;
                }                
            }
            return result;
        }

    }
}
