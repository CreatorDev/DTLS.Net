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

namespace DTLS
{
	internal class ServerHandshake
	{
		private Socket _Socket;
		private int _MaxPacketSize;
        private PSKIdentities _PSKIdentities;
		private byte[] _HelloSecret = new byte[] { 0x12, 0x84, 0x65, 0x94, 0xD5, 0x5E, 0x4B, 0x3A, 0xF3, 0x68, 0x56, 0x6F, 0xD7, 0x1B, 0x09, 0x8A };
		private Dictionary<TCipherSuite, object> _SupportedCipherSuites;
        private bool _RequireClientCertificate;
        private DTLS.Server.ValidatePSKEventHandler _ValidatePSK;

        public Certificate Certificate { get; set; }
		public Org.BouncyCastle.Crypto.AsymmetricKeyParameter PrivateKey { get; set; }
		public Version ServerVersion { get; set; }
		public Sessions Sessions { get; set; }
		private const int HANDSHAKE_DWELL_TIME = 10;
		public static int HandshakeTimeout { get; set; } = 5000;



        public ServerHandshake(Socket socket, int maxPacketSize, PSKIdentities pskIdentities, List<TCipherSuite> supportedCipherSuites, bool requireClientCertificate, DTLS.Server.ValidatePSKEventHandler validatePSK)
		{
			this._Socket = socket;
            _ValidatePSK = validatePSK;
            _MaxPacketSize = maxPacketSize;
            _PSKIdentities = pskIdentities;
			_SupportedCipherSuites = new Dictionary<TCipherSuite, object>();
            _RequireClientCertificate = requireClientCertificate;
            foreach (TCipherSuite item in supportedCipherSuites)
			{
				_SupportedCipherSuites.Add(item, null);
			}
			ServerVersion = new Version(1, 2);

		}


        public void ProcessHandshake(DTLSRecord record)
        {
            SocketAddress address = record.RemoteEndPoint.Serialize();
            Session session = Sessions.GetSession(address);
            byte[] data;
            if ((session != null) && session.IsEncypted(record))
            {
                int count = 0;
                while ((session.Cipher == null) && (count < (HandshakeTimeout / HANDSHAKE_DWELL_TIME)))
                {
                    System.Threading.Thread.Sleep(HANDSHAKE_DWELL_TIME);
                    count++;
                }

                if (session.Cipher == null)
                {
                    throw new Exception($"HandshakeTimeout: >{HandshakeTimeout}");
                }

                if (session.Cipher != null)
                {
                    long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                    data = session.Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
                }
                else
                    data = record.Fragment;
            }
            else
                data = record.Fragment;
            using (MemoryStream stream = new MemoryStream(data))
            {
                HandshakeRecord handshakeRecord = HandshakeRecord.Deserialise(stream);
                if (handshakeRecord != null)
                {
#if DEBUG
                    Console.WriteLine(handshakeRecord.MessageType.ToString());
#endif
                    switch (handshakeRecord.MessageType)
                    {
                        case THandshakeType.HelloRequest:
                            //HelloReq
                            break;
                        case THandshakeType.ClientHello:
                            ClientHello clientHello = ClientHello.Deserialise(stream);
                            if (clientHello != null)
                            {

                                byte[] cookie = clientHello.CalculateCookie(record.RemoteEndPoint, _HelloSecret);

                                if (clientHello.Cookie == null)
                                {
                                    Version version = clientHello.ClientVersion;
                                    if (ServerVersion < version)
                                        version = ServerVersion;
                                    if (session == null)
                                    {
                                        session = new Session();
                                        session.SessionID = Guid.NewGuid();
                                        session.RemoteEndPoint = record.RemoteEndPoint;
                                        session.Version = version;
                                        Sessions.AddSession(address, session);
                                    }
                                    else
                                    {
                                        session.Reset();
                                        session.Version = version;
                                    }
                                    session.ClientEpoch = record.Epoch;
                                    session.ClientSequenceNumber = record.SequenceNumber;
                                    //session.Handshake.UpdateHandshakeHash(data);
                                    HelloVerifyRequest helloVerifyRequest = new HelloVerifyRequest();
                                    helloVerifyRequest.Cookie = cookie;
                                    helloVerifyRequest.ServerVersion = ServerVersion;
                                    SendResponse(session, (IHandshakeMessage)helloVerifyRequest, 0);

                                }
                                else
                                {

                                    if (session != null && session.Cipher != null && !session.IsEncypted(record))
                                    {
                                        session.Reset();
                                    }

                                    if (TLSUtils.ByteArrayCompare(clientHello.Cookie, cookie))
                                    {
                                        Version version = clientHello.ClientVersion;
                                        if (ServerVersion < version)
                                            version = ServerVersion;
                                        if (clientHello.SessionID == null)
                                        {
                                            if (session == null)
                                            {
                                                session = new Session();
                                                session.NextSequenceNumber();
                                                session.SessionID = Guid.NewGuid();
                                                session.RemoteEndPoint = record.RemoteEndPoint;
                                                Sessions.AddSession(address, session);
                                            }
                                        }
                                        else
                                        {
                                            Guid sessionID = Guid.Empty;
                                            if (clientHello.SessionID.Length >= 16)
                                            {
                                                byte[] receivedSessionID = new byte[16];
                                                Buffer.BlockCopy(clientHello.SessionID, 0, receivedSessionID, 0, 16);
                                                sessionID = new Guid(receivedSessionID);
                                            }
                                            if (sessionID != Guid.Empty)
                                                session = Sessions.GetSession(sessionID);
                                            if (session == null)
                                            {
                                                //need to Find Session
                                                session = new Session();
                                                session.SessionID = Guid.NewGuid();
                                                session.NextSequenceNumber();
                                                session.RemoteEndPoint = record.RemoteEndPoint;
                                                Sessions.AddSession(address, session);
                                                //session.Version = clientHello.ClientVersion;
                                            }
                                        }
                                        session.Version = version;
                                        session.Handshake.InitaliseHandshakeHash(version < DTLSRecord.Version1_2);
                                        session.Handshake.UpdateHandshakeHash(data);
                                        TCipherSuite cipherSuite = TCipherSuite.TLS_NULL_WITH_NULL_NULL;
                                        foreach (TCipherSuite item in clientHello.CipherSuites)
                                        {
                                            if (_SupportedCipherSuites.ContainsKey(item) && CipherSuites.SupportedVersion(item, session.Version) && CipherSuites.SuiteUsable(item, PrivateKey, _PSKIdentities, _ValidatePSK != null))
                                            {
                                                cipherSuite = item;
                                                break;
                                            }
                                        }

                                        TKeyExchangeAlgorithm keyExchangeAlgorithm = CipherSuites.GetKeyExchangeAlgorithm(cipherSuite);

                                        ServerHello serverHello = new ServerHello();
                                        byte[] clientSessionID = new byte[32];
                                        byte[] temp = session.SessionID.ToByteArray();
                                        Buffer.BlockCopy(temp, 0, clientSessionID, 0, 16);
                                        Buffer.BlockCopy(temp, 0, clientSessionID, 16, 16);

                                        serverHello.SessionID = clientSessionID;// session.SessionID.ToByteArray();
                                        serverHello.Random = new RandomData();
                                        serverHello.Random.Generate();
                                        serverHello.CipherSuite = (ushort)cipherSuite;
                                        serverHello.ServerVersion = session.Version;

                                        THashAlgorithm hash = THashAlgorithm.SHA256;
                                        TEllipticCurve curve = TEllipticCurve.secp521r1;
                                        if (clientHello.Extensions != null)
                                        {
                                            foreach (Extension extension in clientHello.Extensions)
                                            {
                                                if (extension.SpecifcExtension is ClientCertificateTypeExtension)
                                                {
                                                    ClientCertificateTypeExtension clientCertificateType = extension.SpecifcExtension as ClientCertificateTypeExtension;
                                                    //TCertificateType certificateType = TCertificateType.Unknown;
                                                    //foreach (TCertificateType item in clientCertificateType.CertificateTypes)
                                                    //{

                                                    //}
                                                    //serverHello.AddExtension(new ClientCertificateTypeExtension(certificateType));
                                                }
                                                else if (extension.SpecifcExtension is EllipticCurvesExtension)
                                                {
                                                    EllipticCurvesExtension ellipticCurves = extension.SpecifcExtension as EllipticCurvesExtension;
                                                    foreach (TEllipticCurve item in ellipticCurves.SupportedCurves)
                                                    {
                                                        if (EllipticCurveFactory.SupportedCurve(item))
                                                        {
                                                            curve = item;
                                                            break;
                                                        }
                                                    }
                                                }
                                                else if (extension.SpecifcExtension is ServerCertificateTypeExtension)
                                                {
                                                    //serverHello.AddExtension();
                                                }
                                                else if (extension.SpecifcExtension is SignatureAlgorithmsExtension)
                                                {
                                                    SignatureAlgorithmsExtension signatureAlgorithms = extension.SpecifcExtension as SignatureAlgorithmsExtension;
                                                    foreach (SignatureHashAlgorithm item in signatureAlgorithms.SupportedAlgorithms)
                                                    {
                                                        if (item.Signature == TSignatureAlgorithm.ECDSA)
                                                        {
                                                            hash = item.Hash;
                                                            break;
                                                        }
                                                    }
                                                }
                                            }

                                        }

                                        session.Handshake.CipherSuite = cipherSuite;
                                        session.Handshake.ClientRandom = clientHello.Random;
                                        session.Handshake.ServerRandom = serverHello.Random;


                                        if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_ECDSA)
                                        {
                                            EllipticCurvePointFormatsExtension pointFormatsExtension = new EllipticCurvePointFormatsExtension();
                                            pointFormatsExtension.SupportedPointFormats.Add(TEllipticCurvePointFormat.Uncompressed);
                                            serverHello.AddExtension(pointFormatsExtension);
                                        }
                                        session.Handshake.MessageSequence = 1;
                                        SendResponse(session, serverHello, session.Handshake.MessageSequence);
                                        session.Handshake.MessageSequence++;

                                        if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_ECDSA)
                                        {
                                            if (Certificate != null)
                                            {
                                                SendResponse(session, Certificate, session.Handshake.MessageSequence);
                                                session.Handshake.MessageSequence++;
                                            }
                                            ECDHEKeyExchange keyExchange = new ECDHEKeyExchange();
                                            keyExchange.Curve = curve;
                                            keyExchange.KeyExchangeAlgorithm = keyExchangeAlgorithm;
                                            keyExchange.ClientRandom = clientHello.Random;
                                            keyExchange.ServerRandom = serverHello.Random;
                                            keyExchange.GenerateEphemeralKey();
                                            session.Handshake.KeyExchange = keyExchange;
                                            if (session.Version == DTLSRecord.DefaultVersion)
                                                hash = THashAlgorithm.SHA1;
                                            ECDHEServerKeyExchange serverKeyExchange = new ECDHEServerKeyExchange(keyExchange, hash, TSignatureAlgorithm.ECDSA, PrivateKey);
                                            SendResponse(session, serverKeyExchange, session.Handshake.MessageSequence);
                                            session.Handshake.MessageSequence++;
                                            if (_RequireClientCertificate)
                                            {
                                                CertificateRequest certificateRequest = new CertificateRequest();
                                                certificateRequest.CertificateTypes.Add(TClientCertificateType.ECDSASign);
                                                certificateRequest.SupportedAlgorithms.Add(new SignatureHashAlgorithm() { Hash = THashAlgorithm.SHA256, Signature = TSignatureAlgorithm.ECDSA });
                                                SendResponse(session, certificateRequest, session.Handshake.MessageSequence);
                                                session.Handshake.MessageSequence++;
                                            }
                                        }
                                        else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_PSK)
                                        {
                                            ECDHEKeyExchange keyExchange = new ECDHEKeyExchange();
                                            keyExchange.Curve = curve;
                                            keyExchange.KeyExchangeAlgorithm = keyExchangeAlgorithm;
                                            keyExchange.ClientRandom = clientHello.Random;
                                            keyExchange.ServerRandom = serverHello.Random;
                                            keyExchange.GenerateEphemeralKey();
                                            session.Handshake.KeyExchange = keyExchange;
                                            ECDHEPSKServerKeyExchange serverKeyExchange = new ECDHEPSKServerKeyExchange(keyExchange);
                                            SendResponse(session, serverKeyExchange, session.Handshake.MessageSequence);
                                            session.Handshake.MessageSequence++;

                                        }
                                        else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                                        {
                                            PSKKeyExchange keyExchange = new PSKKeyExchange();
                                            keyExchange.KeyExchangeAlgorithm = keyExchangeAlgorithm;
                                            keyExchange.ClientRandom = clientHello.Random;
                                            keyExchange.ServerRandom = serverHello.Random;
                                            session.Handshake.KeyExchange = keyExchange;
                                            //Need to be able to hint identity?? for PSK if not hinting don't really need key exchange message
                                            //PSKServerKeyExchange serverKeyExchange = new PSKServerKeyExchange();
                                            //SendResponse(session, serverKeyExchange, session.Handshake.MessageSequence);
                                            //session.Handshake.MessageSequence++;
                                        }
                                        SendResponse(session, new ServerHelloDone(), session.Handshake.MessageSequence);
                                        session.Handshake.MessageSequence++;
                                    }
                                }
                            }
                            break;
                        case THandshakeType.ServerHello:
                            break;
                        case THandshakeType.HelloVerifyRequest:
                            break;
                        case THandshakeType.Certificate:
                            Certificate clientCertificate = Certificate.Deserialise(stream, TCertificateType.X509);
                            if (clientCertificate.CertChain.Count > 0)
                            {
                                session.CertificateInfo = Certificates.GetCertificateInfo(clientCertificate.CertChain[0], TCertificateFormat.CER);                                
                            }
                            session.Handshake.UpdateHandshakeHash(data);
                            break;
                        case THandshakeType.ServerKeyExchange:
                            break;
                        case THandshakeType.CertificateRequest:
                            break;
                        case THandshakeType.ServerHelloDone:
                            break;
                        case THandshakeType.CertificateVerify:
                            CertificateVerify certificateVerify = CertificateVerify.Deserialise(stream, session.Version);
                            session.Handshake.UpdateHandshakeHash(data);
                            break;
                        case THandshakeType.ClientKeyExchange:
                            if ((session == null) || (session.Handshake.KeyExchange == null))
                            {

                            }
                            else
                            {
                                session.Handshake.UpdateHandshakeHash(data);
                                byte[] preMasterSecret = null;
                                if (session.Handshake.KeyExchange.KeyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_ECDSA)
                                {
                                    ECDHEClientKeyExchange clientKeyExchange = ECDHEClientKeyExchange.Deserialise(stream);
                                    if (clientKeyExchange != null)
                                    {
                                        ECDHEKeyExchange ecKeyExchange = session.Handshake.KeyExchange as ECDHEKeyExchange;
                                        preMasterSecret = ecKeyExchange.GetPreMasterSecret(clientKeyExchange.PublicKeyBytes);
                                    }
                                }
                                else if (session.Handshake.KeyExchange.KeyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_PSK)
                                {
                                    ECDHEPSKClientKeyExchange clientKeyExchange = ECDHEPSKClientKeyExchange.Deserialise(stream);
                                    if (clientKeyExchange != null)
                                    {
                                        session.PSKIdentity = Encoding.UTF8.GetString(clientKeyExchange.PSKIdentity);
                                        byte[] psk = _PSKIdentities.GetKey(clientKeyExchange.PSKIdentity);

                                        if (psk == null)
                                        {
                                            psk = _ValidatePSK(clientKeyExchange.PSKIdentity);
                                            if (psk != null)
                                            {
                                                _PSKIdentities.AddIdentity(clientKeyExchange.PSKIdentity, psk);
                                            }
                                        }

                                        if (psk != null)
                                        {
                                            ECDHEKeyExchange ecKeyExchange = session.Handshake.KeyExchange as ECDHEKeyExchange;
                                            byte[] otherSecret = ecKeyExchange.GetPreMasterSecret(clientKeyExchange.PublicKeyBytes);
                                            preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, psk);

                                        }
                                    }
                                }
                                else if (session.Handshake.KeyExchange.KeyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                                {
                                    PSKClientKeyExchange clientKeyExchange = PSKClientKeyExchange.Deserialise(stream);
                                    if (clientKeyExchange != null)
                                    {
                                        session.PSKIdentity = Encoding.UTF8.GetString(clientKeyExchange.PSKIdentity);
                                        byte[] psk = _PSKIdentities.GetKey(clientKeyExchange.PSKIdentity);

                                        if (psk == null)
                                        {
                                            psk = _ValidatePSK(clientKeyExchange.PSKIdentity);
                                            if (psk != null)
                                            {
                                                _PSKIdentities.AddIdentity(clientKeyExchange.PSKIdentity, psk);
                                            }
                                        }

                                        if (psk != null)
                                        {
                                            ECDHEKeyExchange ecKeyExchange = session.Handshake.KeyExchange as ECDHEKeyExchange;
                                            byte[] otherSecret = new byte[psk.Length];
                                            preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, psk);
                                        }
                                    }
                                }

                                if (preMasterSecret != null)
                                {
                                    //session.MasterSecret = TLSUtils.CalculateMasterSecret(preMasterSecret, session.KeyExchange);
                                    //TLSUtils.AssignCipher(session);

                                    session.Cipher = TLSUtils.AssignCipher(preMasterSecret, false, session.Version, session.Handshake);
                                }
                            }
                            break;
                        case THandshakeType.Finished:
                            Finished finished = Finished.Deserialise(stream);
                            if (session != null)
                            {
                                byte[] handshakeHash = session.Handshake.GetHash();
                                byte[] calculatedVerifyData = TLSUtils.GetVerifyData(session.Version,session.Handshake,false, true, handshakeHash);
#if DEBUG
                                Console.Write("Handshake Hash:");
                                TLSUtils.WriteToConsole(handshakeHash);
                                Console.Write("Sent Verify:");
                                TLSUtils.WriteToConsole(finished.VerifyData);
                                Console.Write("Calc Verify:");
                                TLSUtils.WriteToConsole(calculatedVerifyData);
#endif
                                if (TLSUtils.ByteArrayCompare(finished.VerifyData, calculatedVerifyData))
                                {

                                    SendChangeCipherSpec(session);
                                    session.Handshake.UpdateHandshakeHash(data);
                                    handshakeHash = session.Handshake.GetHash();
                                    Finished serverFinished = new Finished();
                                    serverFinished.VerifyData = TLSUtils.GetVerifyData(session.Version,session.Handshake,false, false, handshakeHash);
                                    SendResponse(session, serverFinished, session.Handshake.MessageSequence);
                                    session.Handshake.MessageSequence++;
                                }
                                else
                                {
                                    throw new Exception();
                                }
                            }
                            break;
                        default:
                            break;
                    }
                }
            }
        }



		private void SendResponse(Session session, IHandshakeMessage handshakeMessage, ushort messageSequence)
		{
			int size = handshakeMessage.CalculateSize(session.Version);
			int maxPayloadSize = _MaxPacketSize - DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD;
			if (size > maxPayloadSize)
			{

			}
			else
			{
				
				DTLSRecord record = new DTLSRecord();
				record.RecordType = TRecordType.Handshake;
				record.Epoch = session.Epoch;
				record.SequenceNumber = session.NextSequenceNumber();
				record.Fragment = new byte[HandshakeRecord.RECORD_OVERHEAD + size];
				if (session.Version != null)
					record.Version = session.Version;
				HandshakeRecord handshakeRecord = new HandshakeRecord();
				handshakeRecord.MessageType = handshakeMessage.MessageType;
				handshakeRecord.MessageSeq = messageSequence;
				handshakeRecord.Length = (uint)size;
				handshakeRecord.FragmentLength = (uint)size;
				using (MemoryStream stream = new MemoryStream(record.Fragment))
				{
					handshakeRecord.Serialise(stream);
					handshakeMessage.Serialise(stream, session.Version);
				}
                if (handshakeMessage.MessageType != THandshakeType.HelloVerifyRequest)
                {
                    session.Handshake.UpdateHandshakeHash(record.Fragment);
                }
                int responseSize = DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD + size;
                if (session.Cipher != null)
                {
                   long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;                   
                   record.Fragment = session.Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
                   responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                }
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

		private void SendResponseEnd(Session session, IHandshakeMessage handshakeMessage, ushort messageSequence)
		{
			int size = handshakeMessage.CalculateSize(session.Version);
			int maxPayloadSize = _MaxPacketSize - DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD;
			if (size > maxPayloadSize)
			{

			}
			else
			{
				DTLSRecord record = CreateRecord(session, handshakeMessage, messageSequence);
				session.Handshake.MessageSequence++;
				DTLSRecord recordEnd = CreateRecord(session, new ServerHelloDone(), session.Handshake.MessageSequence);
				session.Handshake.MessageSequence++;
				int responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length + DTLSRecord.RECORD_OVERHEAD + recordEnd.Fragment.Length;

				byte[] response = new byte[responseSize];
				using (MemoryStream stream = new MemoryStream(response))
				{
					record.Serialise(stream);
					recordEnd.Serialise(stream);
				}
                SocketAsyncEventArgs parameters = new SocketAsyncEventArgs()
                {
                    RemoteEndPoint = session.RemoteEndPoint
                };
                parameters.SetBuffer(response, 0, responseSize);
                _Socket.SendToAsync(parameters);
			}


		}

		private DTLSRecord CreateRecord(Session session, IHandshakeMessage handshakeMessage, ushort messageSequence)
		{
			int size = handshakeMessage.CalculateSize(session.Version);
			DTLSRecord record = new DTLSRecord();
			record.RecordType = TRecordType.Handshake;
			record.Epoch = session.Epoch;
			record.SequenceNumber = session.NextSequenceNumber();
			record.Fragment = new byte[HandshakeRecord.RECORD_OVERHEAD + size];
			if (session.Version != null)
				record.Version = session.Version;
			HandshakeRecord handshakeRecord = new HandshakeRecord();
			handshakeRecord.MessageType = handshakeMessage.MessageType;
			handshakeRecord.MessageSeq = messageSequence;
			handshakeRecord.Length = (uint)size;
			handshakeRecord.FragmentLength = (uint)size;
			using (MemoryStream stream = new MemoryStream(record.Fragment))
			{
				handshakeRecord.Serialise(stream);
				handshakeMessage.Serialise(stream, session.Version);
			}
			if (handshakeMessage.MessageType != THandshakeType.HelloVerifyRequest)
			{
				session.Handshake.UpdateHandshakeHash(record.Fragment);
			}
			if (session.Cipher != null)
			{
				long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
				record.Fragment = session.Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
			}
			return record;
		}


		private void SendChangeCipherSpec(Session session)
		{
			int size = 1;
			int responseSize = DTLSRecord.RECORD_OVERHEAD + size;
			byte[] response = new byte[responseSize];
			DTLSRecord record = new DTLSRecord();
			record.RecordType = TRecordType.ChangeCipherSpec;
			record.Epoch = session.Epoch;
			record.SequenceNumber = session.NextSequenceNumber();
			record.Fragment = new byte[size];
			record.Fragment[0] = 1;
			if (session.Version != null)
				record.Version = session.Version;
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
            session.ChangeEpoch();
		}

	}
}
