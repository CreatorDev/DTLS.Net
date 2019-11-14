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
using System.Linq;

namespace DTLS
{
    public class PSKIdentities: IEqualityComparer<byte[]>
    {
        private readonly Dictionary<byte[], PSKIdentity> _Identities;

        public int Count => this._Identities.Count;

        public PSKIdentities() => this._Identities = new Dictionary<byte[], PSKIdentity>(10, this);

        public void AddIdentity(byte[] identity, byte[] key)
        {
            if(identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var pskIdentity = new PSKIdentity() { Identity = identity, Key = key };
            this._Identities.Add(pskIdentity.Identity, pskIdentity);
        }
        
        public void AddIdentity(string identity, byte[] key)
        {
            if (string.IsNullOrWhiteSpace(identity))
            {
                throw new ArgumentNullException(nameof(identity));
            }

            if (key == null)
            {
                throw new ArgumentNullException(nameof(key));
            }

            var pskIdentity = new PSKIdentity() { Identity = Encoding.UTF8.GetBytes(identity), Key = key };
            this._Identities.Add(pskIdentity.Identity, pskIdentity);
        }

        public byte[] GetKey(byte[] identity)
        {
            if (identity == null)
            {
                throw new ArgumentNullException(nameof(identity));
            }
            
            if (this._Identities.TryGetValue(identity, out var pskIdentity))
            {
                return pskIdentity.Key;
            }

            return null;
        }

        internal PSKIdentity GetRandom()
        {
            PSKIdentity result = null;
            if (this._Identities.Count > 0)
            {
                var random = new Random();
                var index = random.Next(this._Identities.Count);
                var count = 0;
                foreach (var identity in this._Identities.Keys)
                {
                    if (count == index)
                    {
                        this._Identities.TryGetValue(identity, out result);
                        break;
                    }
                    count++;
                }
            }
            return result;
        }

        private static byte[] HexToBytes(string hex)
        {
            if (string.IsNullOrWhiteSpace(hex))
            {
                throw new ArgumentNullException(nameof(hex));
            }

            var result = new byte[hex.Length / 2];
            var count = 0;
            for (var index = 0; index < hex.Length; index += 2)
            {
                result[count] = Convert.ToByte(hex.Substring(index, 2), 16);
                count++;
            }
            return result;
        }

        public void LoadFromFile(string fileName)
        {
            if (string.IsNullOrWhiteSpace(fileName))
            {
                throw new ArgumentNullException(nameof(fileName));
            }

            if (!File.Exists(fileName))
            {
                return;
            }

            using (var reader = XmlReader.Create(fileName))
            {
                while (reader.Read())
                {
                    if ((reader.NodeType != XmlNodeType.Element) || (reader.Name != "Identity") || !reader.HasAttributes)
                    {
                        continue;
                    }

                    string name = null;
                    byte[] key = null;

                    reader.MoveToFirstAttribute();
                    do
                    {
                        if (reader.Name == "name")
                        {
                            name = reader.Value;
                        }
                        else if (reader.Name == "key")
                        {
                            key = HexToBytes(reader.Value);
                        }
                    } while (reader.MoveToNextAttribute());

                    reader.MoveToElement();
                    if ((name != null) && (key != null))
                    {
                        this.AddIdentity(name, key);
                    }
                }
            }
        }

        bool IEqualityComparer<byte[]>.Equals(byte[] x, byte[] y)
        {
            if(x == null)
            {
                throw new ArgumentNullException(nameof(x));
            }

            if(y == null)
            {
                throw new ArgumentNullException(nameof(y));
            }

            return x.SequenceEqual(y);
        }

        int IEqualityComparer<byte[]>.GetHashCode(byte[] obj)
        {
            if (obj == null)
            {
                throw new ArgumentNullException(nameof(obj));
            }

            var result = 0;
            for (var i = 0; i < obj.Length; i++)
            {
                switch (i % 4)
                {
                    case 0:
                        {
                            result = result | obj[i];
                            break;
                        }
                    case 1:
                        {
                            result = result | (obj[i] << 8);
                            break;
                        }
                    case 2:
                        {
                            result = result | (obj[i] << 16);
                            break;
                        }
                    case 3:
                        {
                            result = result | (obj[i] << 24);
                            break;
                        }
                    default:
                        {
                            break;
                        }
                }                
            }

            return result;
        }
    }
}