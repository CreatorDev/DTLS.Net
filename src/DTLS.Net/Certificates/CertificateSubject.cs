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

using Org.BouncyCastle.Asn1.X509;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace DTLS
{
    public class CertificateSubject
    {
        public string CommonName { get; set; }

        public string Organistion { get; set; }

        public string OrganistionUnit { get; set; }

        public string Location { get; set; }

        public string State { get; set; }

        public string Country { get; set; }

        public CertificateSubject()
        {

        }

        internal CertificateSubject(X509CertificateStructure cert)
        {
            IList ids = cert.Subject.GetOidList();
            IList values = cert.Subject.GetValueList();
            for (int index = 0; index < ids.Count; index++)
            {
                if (X509Name.CN.Equals(ids[index]))
                {
                    CommonName = (string)values[index];
                }
                else if (X509Name.O.Equals(ids[index]))
                {
                    Organistion = (string)values[index];
                }
                else if (X509Name.OU.Equals(ids[index]))
                {
                    OrganistionUnit = (string)values[index];
                }
                else if (X509Name.L.Equals(ids[index]))
                {
                    Location = (string)values[index];
                }
                else if (X509Name.ST.Equals(ids[index]))
                {
                    State = (string)values[index];
                }
                else if (X509Name.C.Equals(ids[index]))
                {
                    Country = (string)values[index];
                }
            }
        }    
    }
}
