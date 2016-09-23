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
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace DTLS
{
	public class Server
	{
        public delegate void DataReceivedEventHandler(System.Net.EndPoint endPoint, byte[] data);
        public event DataReceivedEventHandler DataReceived;

        public delegate byte[] ValidatePSKEventHandler(byte[] identity);
        public event ValidatePSKEventHandler ValidatePSK;

        private int _ReceiveBufferSize;
        private int _SendBufferSize;
		private int _MaxPacketSize = 1440;
		private Socket _Socket;
		private EndPoint _LocalEndPoint;
		private ServerHandshake _Handshake;
		private List<TCipherSuite> _SupportedCipherSuites;
		private Certificate _Certificate;
		private Org.BouncyCastle.Crypto.AsymmetricKeyParameter _PrivateKey;
		private Sessions _Sessions;
        private PSKIdentities _PSKIdentities;
        private bool _RequireClientCertificate;

        public EndPoint LocalEndPoint
        {
            get { return _LocalEndPoint; }
        }

		public int MaxPacketSize
		{
			get { return _MaxPacketSize; }
			set { _MaxPacketSize = value; }
		}

        public PSKIdentities PSKIdentities
		{
            get { return _PSKIdentities; }
            set { _PSKIdentities = value; }
		}       

        public int ReceiveBufferSize
        {
            get { return _ReceiveBufferSize; }
            set 
            {
                _ReceiveBufferSize = value;
                if (_Socket != null)
                    _Socket.ReceiveBufferSize = value;
            }
        }

        public bool RequireClientCertificate
        {
            get { return _RequireClientCertificate; }
            set { _RequireClientCertificate = value; }
        }       

        public int SendBufferSize
        {
            get { return _SendBufferSize; }
            set 
            { 
                _SendBufferSize = value;
                if (_Socket != null)
                    _Socket.SendBufferSize = value;

            }
        }

        public List<TCipherSuite> SupportedCipherSuites
        {
            get
            {
                return _SupportedCipherSuites;
            }
        }

		public Server(EndPoint localEndPoint)
		{
			_LocalEndPoint = localEndPoint;
			_Sessions = new Sessions();
            _PSKIdentities = new PSKIdentities();
            _SupportedCipherSuites = new List<TCipherSuite>();
		}

        public Server(EndPoint localEndPoint, List<TCipherSuite> supportedCipherSuites)
        {
            _LocalEndPoint = localEndPoint;
            _Sessions = new Sessions();
            _PSKIdentities = new PSKIdentities();
            _SupportedCipherSuites = supportedCipherSuites;
        }

        private void CheckSession(Session session, DTLSRecord record)
        {
            if ((session.ClientEpoch == record.Epoch) && (session.ClientSequenceNumber == record.SequenceNumber))
            {
                ThreadPool.QueueUserWorkItem(ProcessRecord, record);
            }
            else if (session.ClientEpoch > record.Epoch)
            {
                ThreadPool.QueueUserWorkItem(ProcessRecord, record);
            }
            else if ((session.ClientEpoch == record.Epoch) && (session.ClientSequenceNumber > record.SequenceNumber))
            {
                ThreadPool.QueueUserWorkItem(ProcessRecord, record);
            }
            else
            {
                bool canProcessNow = false;
                lock (session)
                {
                    if ((session.ClientSequenceNumber == record.SequenceNumber) && (session.ClientEpoch == record.Epoch))
                    {
                        canProcessNow = true;
                    }
                    else
                    {
                        session.Records.Add(record);
                    }
                }
                if (canProcessNow)
                    CheckSession(session, record);
            }
        }

		public void LoadCertificateFromPem(string filename)
		{
			using (FileStream stream = File.OpenRead(filename))
			{
				LoadCertificateFromPem(stream);
			}
		}

		public void LoadCertificateFromPem(Stream stream)
		{
			List<byte[]> chain = new List<byte[]>();
			PemReader reader = new PemReader(new StreamReader(stream));
			PemObject pem = reader.ReadPemObject();

			while (pem != null)
			{
				if (pem.Type.EndsWith("CERTIFICATE"))
				{
					chain.Add(pem.Content);
				}
                else if (pem.Type.EndsWith("PRIVATE KEY"))
                {
                    _PrivateKey = Certificates.GetPrivateKeyFromPEM(pem);
                }
				pem = reader.ReadPemObject();
			}
			_Certificate = new Certificate();
			_Certificate.CertChain = chain;
			_Certificate.CertificateType = TCertificateType.X509;
		}

        public string GetClientPSKIdentity(EndPoint clientEndPoint)
        {
            string result = null;
            SocketAddress address = clientEndPoint.Serialize();
            Session session = _Sessions.GetSession(address);
            if (session != null)
                result = session.PSKIdentity;
            return result;
        }

        public CertificateInfo GetClientCertificateInfo(EndPoint clientEndPoint)
        {
            CertificateInfo result = null;
            SocketAddress address = clientEndPoint.Serialize();
            Session session = _Sessions.GetSession(address);
            if (session != null)
                result = session.CertificateInfo;
            return result;
        }

        private void ProcessRecord(object state)
        {
            DTLSRecord record = state as DTLSRecord;
            if (record != null)
            {
                SocketAddress address = null;
                Session session = null;
                try
                {
                    address = record.RemoteEndPoint.Serialize();
                    session = _Sessions.GetSession(address);
                    if (session == null)
                    {
                        ProcessRecord(address, session, record);
                        session = _Sessions.GetSession(address);
                        if (session != null)
                        {
                            lock (session)
                            {
                                if (record.RecordType != TRecordType.ChangeCipherSpec)
                                    session.ClientSequenceNumber++;
                            }
                        }
                    }
                    else
                    {
                        bool processRecord = false;
                        if ((session.ClientEpoch == record.Epoch) && (session.ClientSequenceNumber == record.SequenceNumber))
                        {
                            processRecord = true;
                        }
                        else if (session.ClientEpoch > record.Epoch)
                        {
                            processRecord = true;
                        }
                        else if ((session.ClientEpoch == record.Epoch) && (session.ClientSequenceNumber > record.SequenceNumber))
                        {
                            processRecord = true;
                        }
                        if (processRecord)
                        {
                            do
                            {
                                ProcessRecord(address, session, record);
                                lock (session)
                                {
                                    if (record.RecordType != TRecordType.ChangeCipherSpec)
                                        session.ClientSequenceNumber++;
                                }
                                record = session.Records.PeekRecord();
                                if (record != null)
                                {
                                    if ((session.ClientSequenceNumber == record.SequenceNumber) && (session.ClientEpoch == record.Epoch))
                                    {
                                        session.Records.RemoveRecord();
                                    }
                                    else
                                    {
                                        record = null;
                                    }
                                }

                            } while (record != null);
                        }
                    }
                }
                catch (Org.BouncyCastle.Crypto.Tls.TlsFatalAlert ex)
                {
                    SendAlert(session, address, TAlertLevel.Fatal, (TAlertDescription)ex.AlertDescription);
                }
                catch
                {
                    SendAlert(session, address, TAlertLevel.Fatal, TAlertDescription.InternalError);
                }
            }
        }

        private void ProcessRecord(SocketAddress address, Session session, DTLSRecord record)
        {
            try
            {
#if DEBUG
            Console.WriteLine(record.RecordType.ToString());
#endif
                switch (record.RecordType)
                {
                    case TRecordType.ChangeCipherSpec:
                        if (session != null)
                        {
                            session.ClientEpoch++;
                            session.ClientSequenceNumber = 0;
                            session.SetEncyptChange(record);
                        }
                        break;
                    case TRecordType.Alert:
                        if (session != null)
                        {
                            AlertRecord alertRecord;
                            try
                            {
                                if (session.Cipher == null)
                                {
                                    alertRecord = AlertRecord.Deserialise(record.Fragment);
                                }
                                else
                                {
                                    long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                                    byte[] data = session.Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.Alert, record.Fragment, 0, record.Fragment.Length);
                                    alertRecord = AlertRecord.Deserialise(data);
                                }
                            }
                            catch
                            {
                                alertRecord = new AlertRecord();
                                alertRecord.AlertLevel = TAlertLevel.Fatal;
                            }
                            if (alertRecord.AlertLevel == TAlertLevel.Fatal)
                                _Sessions.Remove(session, address);
                            else if ((alertRecord.AlertLevel == TAlertLevel.Warning) || (alertRecord.AlertDescription == TAlertDescription.CloseNotify))
                            {
                                if (alertRecord.AlertDescription == TAlertDescription.CloseNotify)
                                    SendAlert(session, address, TAlertLevel.Warning, TAlertDescription.CloseNotify);
                                _Sessions.Remove(session, address);
                            }
                        }
                        break;
                    case TRecordType.Handshake:
                        _Handshake.ProcessHandshake(record);
                        break;
                    case TRecordType.ApplicationData:
                        if (session != null)
                        {
                            if (session.Cipher != null)
                            {
                                long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                                byte[] data = session.Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.ApplicationData, record.Fragment, 0, record.Fragment.Length);
                                if (DataReceived != null)
                                {
                                    DataReceived(record.RemoteEndPoint, data);
                                }
                            }
                        }
                        break;
                    default:
                        break;
                }
            }
#if DEBUG
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
#else
            catch
            {
#endif
                SendAlert(session, address, TAlertLevel.Fatal, TAlertDescription.InternalError);
            }
        }

         private void ReceiveCallback(object sender, SocketAsyncEventArgs e)
		{
            if (e.BytesTransferred == 0)
            {

            }
            else
            {
                int count = e.BytesTransferred;
                byte[] data = new byte[count];
                Buffer.BlockCopy(e.Buffer, 0, data, 0, count);
                MemoryStream stream = new MemoryStream(data);
                while (stream.Position < stream.Length)
                {
                    DTLSRecord record = DTLSRecord.Deserialise(stream);
                    if (record != null)
                    {
                        record.RemoteEndPoint = e.RemoteEndPoint;
                        SocketAddress address = record.RemoteEndPoint.Serialize();
                        Session session = _Sessions.GetSession(address);
                        if (session == null)
                        {
                            ThreadPool.QueueUserWorkItem(ProcessRecord, record);
                        }
                        else
                        {
                            CheckSession(session, record);
                        }
                    }
                }
                Socket socket = sender as Socket;
                if (socket != null)
                {
                    System.Net.EndPoint remoteEndPoint;
                    if (socket.AddressFamily == AddressFamily.InterNetwork)
                        remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
                    else
                        remoteEndPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
                    e.RemoteEndPoint = remoteEndPoint;
                    e.SetBuffer(0, 4096);
                    socket.ReceiveFromAsync(e);
                }
            }
		}
               
		private Socket SetupSocket(AddressFamily addressFamily)
		{
			Socket result = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (addressFamily == AddressFamily.InterNetworkV6)
            {
                result.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
            }
            if (Environment.OSVersion.Platform != PlatformID.Unix)
            {
                // Do not throw SocketError.ConnectionReset by ignoring ICMP Port Unreachable
                const Int32 SIO_UDP_CONNRESET = -1744830452;
                result.IOControl(SIO_UDP_CONNRESET, new Byte[] { 0 }, null);
            }
			return result;
		}

        public void Send(EndPoint remoteEndPoint, byte[] data)
        {
            SocketAddress address = remoteEndPoint.Serialize();
            Session session = _Sessions.GetSession(address);
            if (session != null)
            {
                try
                {
                    DTLSRecord record = new DTLSRecord();
                    record.RecordType = TRecordType.ApplicationData;
                    record.Epoch = session.Epoch;
                    record.SequenceNumber = session.NextSequenceNumber();
                    if (session.Version != null)
                        record.Version = session.Version;
                    long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                    record.Fragment = session.Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.ApplicationData, data, 0, data.Length);
                    int responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                    byte[] response = new byte[responseSize];
                    using (MemoryStream stream = new MemoryStream(response))
                    {
                        record.Serialise(stream);
                    }
                    SocketAsyncEventArgs parameters = new SocketAsyncEventArgs()
                    {
                        RemoteEndPoint = session.RemoteEndPoint
                    };
                    parameters.SetBuffer(response, 0, responseSize);
                    _Socket.SendToAsync(parameters);
                }
#if DEBUG
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
#else
                catch
                {
#endif
                }
            }
        }

        private void SendAlert(Session session, SocketAddress address, TAlertLevel alertLevel, TAlertDescription alertDescription)
        {
            if (session != null)
            {
                DTLSRecord record = new DTLSRecord();
                record.RecordType = TRecordType.Alert;
                record.Epoch = session.Epoch;
                record.SequenceNumber = session.NextSequenceNumber();
                if (session.Version != null)
                    record.Version = session.Version;
                long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;

                byte[] data = new byte[2];
                data[0] = (byte)alertLevel;
                data[1] = (byte)alertDescription;
                if (session.Cipher == null)
                    record.Fragment = data;
                else
                    record.Fragment = session.Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.ApplicationData, data, 0, data.Length);
                int responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                byte[] response = new byte[responseSize];
                using (MemoryStream stream = new MemoryStream(response))
                {
                    record.Serialise(stream);
                }
                SocketAsyncEventArgs parameters = new SocketAsyncEventArgs()
                {
                    RemoteEndPoint = session.RemoteEndPoint
                };
                parameters.SetBuffer(response, 0, responseSize);
                _Socket.SendToAsync(parameters);
            }
        }

		public void Start()
		{
            if (_SupportedCipherSuites.Count == 0)
            {
                _SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8); //Test 1.2
                _SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                _SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                _SupportedCipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8); //Test 1.2
                _SupportedCipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
            }

            _Socket = SetupSocket(_LocalEndPoint.AddressFamily);

			if (_Socket != null)
			{
                _Handshake = new ServerHandshake(_Socket, _MaxPacketSize, _PSKIdentities, _SupportedCipherSuites, _RequireClientCertificate, ValidatePSK);
				_Handshake.Certificate = _Certificate;
				_Handshake.PrivateKey = _PrivateKey;
				_Handshake.Sessions = _Sessions;
				_Socket.Bind(_LocalEndPoint);
				StartReceive(_Socket);
			}

		}

        private void StartReceive(Socket socket)
        {
            SocketAsyncEventArgs parameters = new SocketAsyncEventArgs();
            if (socket.AddressFamily == AddressFamily.InterNetwork)
                parameters.RemoteEndPoint = new IPEndPoint(IPAddress.Any, 0);
            else
                parameters.RemoteEndPoint = new IPEndPoint(IPAddress.IPv6Any, 0);
            parameters.Completed += new EventHandler<SocketAsyncEventArgs>(ReceiveCallback);
            parameters.SetBuffer(new byte[4096], 0, 4096);
            socket.ReceiveFromAsync(parameters);
        }

		public void Stop()
		{
			if (_Socket != null)
			{
				_Socket.Dispose();
				_Socket = null;
			}
		}

	}
}
