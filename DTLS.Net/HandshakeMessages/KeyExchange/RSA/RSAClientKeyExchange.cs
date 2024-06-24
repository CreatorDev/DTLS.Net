using System;
using System.IO;

namespace DTLS
{
    //EncryptedPreMasterSecret
    internal class RSAClientKeyExchange : IHandshakeMessage
    {
        public THandshakeType MessageType => THandshakeType.ClientKeyExchange;

        public byte[] PremasterSecret { get; set; }


        public int CalculateSize(Version version)
        {
            var result = 2;
            if (this.PremasterSecret != null)
            {
                result += this.PremasterSecret.Length;
            }

            return result;
        }

        public void Serialise(Stream stream, Version version)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }
            
            if (this.PremasterSecret == null)
            {
                NetworkByteOrderConverter.WriteUInt16(stream, 0);
            }
            else
            {
                NetworkByteOrderConverter.WriteUInt16(stream, (ushort)this.PremasterSecret.Length);
                stream.Write(this.PremasterSecret, 0, this.PremasterSecret.Length);
            }
        }

        public static RSAClientKeyExchange Deserialise(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            RSAClientKeyExchange result = null;
            var rsaPremasterLength = NetworkByteOrderConverter.ToUInt16(stream);
            if (rsaPremasterLength > 0)
            {
                result = new RSAClientKeyExchange
                {
                    PremasterSecret = new byte[rsaPremasterLength]
                };
                stream.Read(result.PremasterSecret, 0, rsaPremasterLength);
            }
            return result;
        }
    }
}