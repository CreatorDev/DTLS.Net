using Org.BouncyCastle.Crypto.Prng;
using System;
using System.Security.Cryptography;

namespace DTLS
{
    public class CryptoApiRandomGenerator
    : IRandomGenerator
    {
        private readonly RandomNumberGenerator _RndProv;

        public CryptoApiRandomGenerator() => this._RndProv = RandomNumberGenerator.Create();

        public virtual void AddSeedMaterial(byte[] seed)
        {
            // I don't care about the seed
        }

        public virtual void AddSeedMaterial(long seed)
        {
            // I don't care about the seed
        }

        public virtual void NextBytes(byte[] bytes) => this._RndProv.GetBytes(bytes);

        public virtual void NextBytes(byte[] bytes, int start, int len)
        {
            if (start < 0)
            {
                throw new ArgumentException("Start offset cannot be negative", "start");
            }

            if (bytes.Length < (start + len))
            {
                throw new ArgumentException("Byte array too small for requested offset and length");
            }

            if (bytes.Length == len && start == 0)
            {
                this.NextBytes(bytes);
            }
            else
            {
                var tmpBuf = new byte[len];
                this._RndProv.GetBytes(tmpBuf);
                Array.Copy(tmpBuf, 0, bytes, start, len);
            }
        }
    }
}