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
using System.Net;
using System.Collections.Generic;
using System.Collections.Concurrent;
using System.Linq;
using System.Text;

namespace DTLS
{
	internal class Sessions
	{
		private ConcurrentDictionary<SocketAddress, Session> _Sessions;
		private ConcurrentDictionary<Guid, Session> _SessionsByID;
		private List<Session> _SessionList;

		public Sessions()
		{
			_Sessions = new ConcurrentDictionary<SocketAddress, Session>();
			_SessionsByID = new ConcurrentDictionary<Guid, Session>();
			_SessionList = new List<Session>();
		}

		public void AddSession(SocketAddress address, Session session)
		{
			if (_Sessions.TryAdd(address, session))
			{
				_SessionsByID.TryAdd(session.SessionID, session);
				_SessionList.Add(session);
			}
		}

		public Session GetSession(SocketAddress address)
		{
			Session result;
			_Sessions.TryGetValue(address, out result);
			return result;
		}

		public Session GetSession(Guid sessionID)
		{
			Session result;
			_SessionsByID.TryGetValue(sessionID, out result);
			return result;
		}

        public void Remove(Session session, SocketAddress address)
        {
            Session existing;
            _Sessions.TryRemove(address, out session);
            _SessionsByID.TryRemove(session.SessionID, out existing);
            _SessionList.Remove(session);
        }
    }
}
