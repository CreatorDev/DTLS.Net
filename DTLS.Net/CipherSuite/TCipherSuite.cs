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


namespace DTLS
{
    public enum TCipherSuite
    {
        TLS_NULL_WITH_NULL_NULL = 0,

        TLS_RSA_WITH_NULL_MD5 = 0x01,
        TLS_RSA_WITH_NULL_SHA = 0x02,
        TLS_RSA_WITH_NULL_SHA256 = 0x3B,
        TLS_RSA_WITH_RC4_128_MD5 = 0x04,
        TLS_RSA_WITH_RC4_128_SHA = 0x05,
        TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x0A,
        TLS_RSA_WITH_AES_128_CBC_SHA = 0x2F,
        TLS_RSA_WITH_AES_256_CBC_SHA = 0x35,
        TLS_RSA_WITH_AES_128_CBC_SHA256 = 0x3C,
        TLS_RSA_WITH_AES_256_CBC_SHA256 = 0x3D,

        TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA = 0x0D,
        TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA = 0x10,
        TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA = 0x13,
        TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA = 0x16,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA = 0x30,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA = 0x31,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA = 0x32,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA = 0x33,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA = 0x36,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA = 0x37,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA = 0x38,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA = 0x39,
        TLS_DH_DSS_WITH_AES_128_CBC_SHA256 = 0x3E,
        TLS_DH_RSA_WITH_AES_128_CBC_SHA256 = 0x3F,
        TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 = 0x40,
        TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 = 0x67,
        TLS_DH_DSS_WITH_AES_256_CBC_SHA256 = 0x68,
        TLS_DH_RSA_WITH_AES_256_CBC_SHA256 = 0x69,
        TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 = 0x6A,
        TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 = 0x6B,

        TLS_DH_anon_WITH_RC4_128_MD5 = 0x18,
        TLS_DH_anon_WITH_3DES_EDE_CBC_SHA = 0x1B,
        TLS_DH_anon_WITH_AES_128_CBC_SHA = 0x34,
        TLS_DH_anon_WITH_AES_256_CBC_SHA = 0x3A,
        TLS_DH_anon_WITH_AES_128_CBC_SHA256 = 0x6C,
        TLS_DH_anon_WITH_AES_256_CBC_SHA256 = 0x6D,

        TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 = 0xC0AE,
        TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 = 0xC023,
        TLS_PSK_WITH_AES_128_CCM_8 = 0xC0A8,
        TLS_PSK_WITH_AES_128_CBC_SHA256 = 0xAE,
        TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 = 0xC037

    }
}


