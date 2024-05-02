using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace DTLS.Net.Util
{
    public static class NCryptInterop
    {
        private struct BCRYPT_PKCS1_PADDING_INFO
        {
            internal IntPtr _PszAlgId;
        }

        [Flags]
        private enum NCryptSignFlags
        {
            BCRYPT_PAD_PKCS1 = 2,
        }

        [DllImport("ncrypt.dll")]
        private static extern int NCryptSignHash(
            SafeNCryptKeyHandle hKey,
            ref BCRYPT_PKCS1_PADDING_INFO padding,
            ref byte pbHashValue,
            int cbHashValue,
            ref byte pbSignature,
            int cbSignature,
            out int cbResult,
            NCryptSignFlags dwFlags);

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "The RSA items are windows only, however we want to allow for the other types of encryption to be use in other platforms")]
        internal static byte[] SignHashRaw(CngKey key, byte[] hash, int keySize)
        {
            var keySizeBytes = keySize / 8;
            var signature = new byte[keySizeBytes];

            // The Handle property returns a new object each time.
            using (var keyHandle = key.Handle)
            {
                // Leave pszAlgId NULL to "raw sign"
                var paddingInfo = new BCRYPT_PKCS1_PADDING_INFO();

                var result = NCryptSignHash(
                    keyHandle,
                    ref paddingInfo,
                    ref hash[0],
                    hash.Length,
                    ref signature[0],
                    signature.Length,
                    out var cbResult,
                    NCryptSignFlags.BCRYPT_PAD_PKCS1);

                if (result != 0)
                {
                    throw new CryptographicException(result);
                }

                if (cbResult != signature.Length)
                {
                    throw new InvalidOperationException();
                }

                return signature;
            }
        }
    }
}