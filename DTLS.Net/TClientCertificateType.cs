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
    //    enum {
    //    rsa_sign(1), dss_sign(2), rsa_fixed_dh(3), dss_fixed_dh(4),
    //    rsa_ephemeral_dh_RESERVED(5), dss_ephemeral_dh_RESERVED(6),
    //    fortezza_dms_RESERVED(20), 
    //    ecdsa_sign(64), rsa_fixed_ecdh(65),
    //    ecdsa_fixed_ecdh(66), 
    //    (255)
    //} ClientCertificateType;
    internal enum TClientCertificateType
	{
        RSASign = 1, // Certificate containing an RSA key
        DSSSign = 2, // Certificate containing an DSA key
        RSAFixedDiffieHellmanKey = 3, // Certificate containing a static DH key
        DSSFixedDiffieHellmanKey = 4, // Certificate containing a static DH key
        RSAEphemeralDiffieHellmanKey = 5, //RESERVED
        DSSEphemeralDiffieHellmanKey = 6, //RESERVED 
        FortezzaDMS = 20, //RESERVED 
        ECDSASign = 64,     // Certificate MUST contain an ECDSA-capable public key and be signed with ECDSA.
        RSAFixedECDH = 65, // Certificate MUST contain an ECDH-capable public key on the same elliptic curve as the server's long-term ECDH key.This certificate MUST be signed with ECDSA.
        ECDSAFixedECDH = 66, // Certificate MUST contain an ECDH-capable public key on the same elliptic curve as the server's long-term ECDH key.This certificate MUST be signed with RSA.
    }
}