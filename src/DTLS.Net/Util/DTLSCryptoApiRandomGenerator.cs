using Org.BouncyCastle.Crypto.Prng;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace DTLS.Net.Util
{
    public class DTLSCryptoApiRandomGenerator
        : IRandomGenerator
    {
        private readonly RNGCryptoServiceProvider rndProv;

        public DTLSCryptoApiRandomGenerator()
        {
            rndProv = new RNGCryptoServiceProvider();
        }

        #region IRandomGenerator Members

        public virtual void AddSeedMaterial(byte[] seed)
        {
            // I don't care about the seed
        }

        public virtual void AddSeedMaterial(long seed)
        {
            // I don't care about the seed
        }

        public virtual void NextBytes(byte[] bytes)
        {
            rndProv.GetBytes(bytes);
        }

        public virtual void NextBytes(byte[] bytes, int start, int len)
        {
            if (start < 0)
                throw new ArgumentException("Start offset cannot be negative", "start");
            if (bytes.Length < (start + len))
                throw new ArgumentException("Byte array too small for requested offset and length");

            if (bytes.Length == len && start == 0)
            {
                NextBytes(bytes);
            }
            else
            {
                byte[] tmpBuf = new byte[len];
                rndProv.GetBytes(tmpBuf);
                Array.Copy(tmpBuf, 0, bytes, start, len);
            }
        }

        #endregion
    }
}