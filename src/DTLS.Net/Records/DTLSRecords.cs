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

namespace DTLS
{
    internal class DTLSRecords
    {
        private List<DTLSRecord> _Records;

        public DTLSRecords()
        {
            _Records = new List<DTLSRecord>();
        }

        public void Add(DTLSRecord record)
        {
            lock (_Records)
            {
                int index = 0;
                bool added = false;
                while (index < _Records.Count)
                {
                    if (record.Epoch < _Records[index].Epoch)
                    {
                        _Records.Insert(index, record);
                        added = true;
                        break;
                    }
                    if ((record.SequenceNumber < _Records[index].SequenceNumber) && (record.Epoch == _Records[index].Epoch))
                    {
                        _Records.Insert(index, record);
                        added = true;
                        break;
                    }
                    else if ((record.SequenceNumber == _Records[index].SequenceNumber) && (record.Epoch == _Records[index].Epoch))
                    {
                        added = true;
                        break;
                    }
                    index++;
                }
                if (!added)
                    _Records.Add(record);
            }
        }

        public void Clear()
        {

        }

        public DTLSRecord PeekRecord()
        {
            DTLSRecord result = null;
            lock (_Records)
            {
                if (_Records.Count > 0)
                    result = _Records[0];
            }
            return result;
        }

        public void RemoveRecord()
        {
            lock (_Records)
            {
                _Records.RemoveAt(0);
            }
        }
    }
}
