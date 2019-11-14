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
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Net;

namespace DTLS
{
    internal class Sessions
	{
		private readonly ConcurrentDictionary<SocketAddress, Session> _Sessions = new ConcurrentDictionary<SocketAddress, Session>();
        private readonly ConcurrentDictionary<Guid, Session> _SessionsByID = new ConcurrentDictionary<Guid, Session>();
        private readonly List<Session> _SessionList = new List<Session>();

		public void AddSession(SocketAddress address, Session session)
		{
			if (this._Sessions.TryAdd(address, session))
			{
                this._SessionsByID.TryAdd(session.SessionID, session);
                this._SessionList.Add(session);
			}
		}

		public Session GetSession(SocketAddress address)
		{
            this._Sessions.TryGetValue(address, out var result);
            return result;
		}

		public Session GetSession(Guid sessionID)
		{
            this._SessionsByID.TryGetValue(sessionID, out var result);
            return result;
		}

        public void Remove(Session session, SocketAddress address)
        {
            this._Sessions.TryRemove(address, out session);
            this._SessionsByID.TryRemove(session.SessionID, out var existing);
            this._SessionList.Remove(session);
        }
    }
}