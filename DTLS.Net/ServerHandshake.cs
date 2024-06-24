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

using Org.BouncyCastle.Crypto;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Sockets;
using System.Text;
using static DTLS.Server;

namespace DTLS
{
    internal class ServerHandshake
    {
        private readonly bool _RequireClientCertificate;
        private readonly ValidatePSKEventHandler _ValidatePSK;
        private readonly int _MaxPacketSize;
        private readonly byte[] _HelloSecret = new byte[] { 0x12, 0x84, 0x65, 0x94, 0xD5, 0x5E, 0x4B, 0x3A, 0xF3, 0x68, 0x56, 0x6F, 0xD7, 0x1B, 0x09, 0x8A };

        private Socket _Socket;
        private PSKIdentities _PSKIdentities;
		private readonly Dictionary<TCipherSuite, object> _SupportedCipherSuites;

        public Certificate Certificate { get; set; }
		public AsymmetricKeyParameter PrivateKey { get; set; }
		public Version ServerVersion { get; set; }
		public Sessions Sessions { get; set; }

        public ServerHandshake(Socket socket, int maxPacketSize, PSKIdentities pskIdentities, List<TCipherSuite> supportedCipherSuites, 
            bool requireClientCertificate, ValidatePSKEventHandler validatePSK)
		{
            if(supportedCipherSuites == null)
            {
                throw new ArgumentNullException(nameof(supportedCipherSuites));
            }

            this._Socket = socket ?? throw new ArgumentNullException(nameof(socket));
            this._PSKIdentities = pskIdentities ?? throw new ArgumentNullException(nameof(pskIdentities));
            this._ValidatePSK = validatePSK;
            this._MaxPacketSize = maxPacketSize;
            this._RequireClientCertificate = requireClientCertificate;
            this.ServerVersion = new Version(1, 2);

            this._SupportedCipherSuites = new Dictionary<TCipherSuite, object>();
            foreach (var item in supportedCipherSuites)
			{
                this._SupportedCipherSuites.Add(item, null);
			}
		}

        public void ProcessHandshake(DTLSRecord record)
        {
            if(record == null)
            {
                throw new ArgumentNullException(nameof(record));
            }

            var address = record.RemoteEndPoint.Serialize();
            var session = this.Sessions.GetSession(address);
            var data = record.Fragment;
            if ((session != null) && session.IsEncypted(record))
            {
                var count = 0;
                while ((session.Cipher == null) && (count < 50))
                {
                    System.Threading.Thread.Sleep(10);
                    count++;
                }

                if (session.Cipher == null)
                {                    
                    throw new Exception("Need Cipher for Encrypted Session");
                }

                var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                data = session.Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
            }

            using (var stream = new MemoryStream(data))
            {
                var handshakeRecord = HandshakeRecord.Deserialise(stream);
                switch (handshakeRecord.MessageType)
                {
                    case THandshakeType.HelloRequest:
                        {
                            //HelloReq
                            break;
                        }
                    case THandshakeType.ClientHello:
                        {
                            var clientHello = ClientHello.Deserialise(stream);
                            var cookie = clientHello.CalculateCookie(record.RemoteEndPoint, this._HelloSecret);

                            if (clientHello.Cookie == null)
                            {
                                var vers = clientHello.ClientVersion;
                                if (this.ServerVersion < vers)
                                {
                                    vers = this.ServerVersion;
                                }

                                if (session == null)
                                {
                                    session = new Session
                                    {
                                        SessionID = Guid.NewGuid(),
                                        RemoteEndPoint = record.RemoteEndPoint,
                                        Version = vers
                                    };
                                    this.Sessions.AddSession(address, session);
                                }
                                else
                                {
                                    session.Reset();
                                    session.Version = vers;
                                }

                                session.ClientEpoch = record.Epoch;
                                session.ClientSequenceNumber = record.SequenceNumber;

                                var helloVerifyRequest = new HelloVerifyRequest
                                {
                                    Cookie = cookie,
                                    ServerVersion = ServerVersion
                                };

                                this.SendResponse(session, helloVerifyRequest, 0);
                                break;
                            }

                            if (session != null && session.Cipher != null && !session.IsEncypted(record))
                            {
                                session.Reset();
                            }

                            if (!clientHello.Cookie.SequenceEqual(cookie))
                            {
                                break;
                            }

                            var version = clientHello.ClientVersion;
                            if (this.ServerVersion < version)
                            {
                                version = this.ServerVersion;
                            }
                            
                            if (clientHello.SessionID == null)
                            {
                                if (session == null)
                                {
                                    session = new Session();
                                    session.NextSequenceNumber();
                                    session.SessionID = Guid.NewGuid();
                                    session.RemoteEndPoint = record.RemoteEndPoint;
                                    this.Sessions.AddSession(address, session);
                                }
                            }
                            else
                            {
                                if (clientHello.SessionID.Length >= 16)
                                {
                                    session = this.Sessions.GetSession(new Guid(clientHello.SessionID.Take(16).ToArray()));
                                }

                                if (session == null)
                                {
                                    //need to Find Session
                                    session = new Session
                                    {
                                        SessionID = Guid.NewGuid()
                                    };
                                    session.NextSequenceNumber();
                                    session.RemoteEndPoint = record.RemoteEndPoint;
                                    this.Sessions.AddSession(address, session);
                                }
                            }

                            session.Version = version;
                            var cipherSuite = TCipherSuite.TLS_NULL_WITH_NULL_NULL;
                            foreach (TCipherSuite item in clientHello.CipherSuites)
                            {
                                if (this._SupportedCipherSuites.ContainsKey(item) && CipherSuites.SupportedVersion(item, session.Version) && CipherSuites.SuiteUsable(item, this.PrivateKey, this._PSKIdentities, this._ValidatePSK != null))
                                {
                                    cipherSuite = item;
                                    break;
                                }
                            }

                            var clientSessionID = new byte[32];
                            var temp = session.SessionID.ToByteArray();
                            Buffer.BlockCopy(temp, 0, clientSessionID, 0, 16);
                            Buffer.BlockCopy(temp, 0, clientSessionID, 16, 16);

                            var serverHello = new ServerHello
                            {
                                SessionID = clientSessionID,// session.SessionID.ToByteArray();
                                Random = new RandomData(),
                                CipherSuite = (ushort)cipherSuite,
                                ServerVersion = session.Version
                            };
                            serverHello.Random.Generate();

                            session.Handshake.UpdateHandshakeHash(data);
                            session.Handshake.CipherSuite = cipherSuite;
                            session.Handshake.ClientRandom = clientHello.Random;
                            session.Handshake.ServerRandom = serverHello.Random;

                            var hash = THashAlgorithm.SHA256;
                            var curve = TEllipticCurve.secp521r1;
                            if (clientHello.Extensions != null)
                            {
                                foreach (var extension in clientHello.Extensions)
                                {
                                    if (extension.SpecificExtension is ClientCertificateTypeExtension)
                                    {
                                        var clientCertificateType = extension.SpecificExtension as ClientCertificateTypeExtension;
                                        //TCertificateType certificateType = TCertificateType.Unknown;
                                        //foreach (TCertificateType item in clientCertificateType.CertificateTypes)
                                        //{

                                        //}
                                        //serverHello.AddExtension(new ClientCertificateTypeExtension(certificateType));
                                    }
                                    else if (extension.SpecificExtension is EllipticCurvesExtension)
                                    {
                                        var ellipticCurves = extension.SpecificExtension as EllipticCurvesExtension;
                                        foreach (var item in ellipticCurves.SupportedCurves)
                                        {
                                            if (EllipticCurveFactory.SupportedCurve(item))
                                            {
                                                curve = item;
                                                break;
                                            }
                                        }
                                    }
                                    else if (extension.SpecificExtension is ServerCertificateTypeExtension)
                                    {
                                        //serverHello.AddExtension();
                                    }
                                    else if (extension.SpecificExtension is SignatureAlgorithmsExtension)
                                    {
                                        var signatureAlgorithms = extension.SpecificExtension as SignatureAlgorithmsExtension;
                                        foreach (var item in signatureAlgorithms.SupportedAlgorithms)
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

                            var keyExchangeAlgorithm = CipherSuites.GetKeyExchangeAlgorithm(cipherSuite);
                            if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_ECDSA)
                            {
                                var pointFormatsExtension = new EllipticCurvePointFormatsExtension();
                                pointFormatsExtension.SupportedPointFormats.Add(TEllipticCurvePointFormat.Uncompressed);
                                serverHello.AddExtension(pointFormatsExtension);
                            }

                            session.Handshake.MessageSequence = 1;
                            this.SendResponse(session, serverHello, session.Handshake.MessageSequence);
                            session.Handshake.MessageSequence++;

                            if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_ECDSA)
                            {
                                if (this.Certificate != null)
                                {
                                    this.SendResponse(session, this.Certificate, session.Handshake.MessageSequence);
                                    session.Handshake.MessageSequence++;
                                }

                                var keyExchange = new ECDHEKeyExchange
                                {
                                    Curve = curve,
                                    KeyExchangeAlgorithm = keyExchangeAlgorithm,
                                    ClientRandom = clientHello.Random,
                                    ServerRandom = serverHello.Random
                                };

                                keyExchange.GenerateEphemeralKey();
                                session.Handshake.KeyExchange = keyExchange;
                                if (session.Version == DTLSRecord.DefaultVersion)
                                {
                                    hash = THashAlgorithm.SHA1;
                                }

                                var serverKeyExchange = new ECDHEServerKeyExchange(keyExchange, hash, TSignatureAlgorithm.ECDSA, this.PrivateKey);
                                this.SendResponse(session, serverKeyExchange, session.Handshake.MessageSequence);

                                session.Handshake.MessageSequence++;
                                if (this._RequireClientCertificate)
                                {
                                    var certificateRequest = new CertificateRequest();
                                    certificateRequest.CertificateTypes.Add(TClientCertificateType.ECDSASign);
                                    certificateRequest.SupportedAlgorithms.Add(new SignatureHashAlgorithm() { Hash = THashAlgorithm.SHA256, Signature = TSignatureAlgorithm.ECDSA });
                                    this.SendResponse(session, certificateRequest, session.Handshake.MessageSequence);
                                    session.Handshake.MessageSequence++;
                                }
                            }
                            else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_PSK)
                            {
                                var keyExchange = new ECDHEKeyExchange
                                {
                                    Curve = curve,
                                    KeyExchangeAlgorithm = keyExchangeAlgorithm,
                                    ClientRandom = clientHello.Random,
                                    ServerRandom = serverHello.Random
                                };

                                keyExchange.GenerateEphemeralKey();
                                session.Handshake.KeyExchange = keyExchange;
                                var serverKeyExchange = new ECDHEPSKServerKeyExchange(keyExchange);
                                this.SendResponse(session, serverKeyExchange, session.Handshake.MessageSequence);
                                session.Handshake.MessageSequence++;

                            }
                            else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                            {
                                var keyExchange = new PSKKeyExchange
                                {
                                    KeyExchangeAlgorithm = keyExchangeAlgorithm,
                                    ClientRandom = clientHello.Random,
                                    ServerRandom = serverHello.Random
                                };
                                session.Handshake.KeyExchange = keyExchange;
                                //Need to be able to hint identity?? for PSK if not hinting don't really need key exchange message
                                //PSKServerKeyExchange serverKeyExchange = new PSKServerKeyExchange();
                                //SendResponse(session, serverKeyExchange, session.Handshake.MessageSequence);
                                //session.Handshake.MessageSequence++;
                            }
                            this.SendResponse(session, new ServerHelloDone(), session.Handshake.MessageSequence);
                            session.Handshake.MessageSequence++;
                            break;
                        }
                    case THandshakeType.ServerHello:
                        {
                            break;
                        }
                    case THandshakeType.HelloVerifyRequest:
                        {
                            break;
                        }
                    case THandshakeType.Certificate:
                        {
                            var clientCertificate = Certificate.Deserialise(stream, TCertificateType.X509);
                            if (clientCertificate.CertChain.Count > 0)
                            {
                                session.CertificateInfo = Certificates.GetCertificateInfo(clientCertificate.CertChain[0], TCertificateFormat.CER);
                            }
                            session.Handshake.UpdateHandshakeHash(data);
                            break;
                        }
                    case THandshakeType.ServerKeyExchange:
                        {
                            break;
                        }
                    case THandshakeType.CertificateRequest:
                        {
                            break;
                        }
                    case THandshakeType.ServerHelloDone:
                        {
                            break;
                        }
                    case THandshakeType.CertificateVerify:
                        {
                            var certificateVerify = CertificateVerify.Deserialise(stream, session.Version);
                            session.Handshake.UpdateHandshakeHash(data);
                        }
                        break;
                    case THandshakeType.ClientKeyExchange:
                        {
                            if ((session == null) || (session.Handshake.KeyExchange == null))
                            {
                                break;
                            }

                            session.Handshake.UpdateHandshakeHash(data);
                            byte[] preMasterSecret = null;
                            if (session.Handshake.KeyExchange.KeyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_ECDSA)
                            {
                                var clientKeyExchange = ECDHEClientKeyExchange.Deserialise(stream);
                                if (clientKeyExchange != null)
                                {
                                    var ecKeyExchange = session.Handshake.KeyExchange as ECDHEKeyExchange;
                                    preMasterSecret = ecKeyExchange.GetPreMasterSecret(clientKeyExchange.PublicKeyBytes);
                                }
                            }
                            else if (session.Handshake.KeyExchange.KeyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_PSK)
                            {
                                var clientKeyExchange = ECDHEPSKClientKeyExchange.Deserialise(stream);
                                if (clientKeyExchange != null)
                                {
                                    session.PSKIdentity = Encoding.UTF8.GetString(clientKeyExchange.PSKIdentity);
                                    var psk = this._PSKIdentities.GetKey(clientKeyExchange.PSKIdentity);

                                    if (psk == null)
                                    {
                                        psk = this._ValidatePSK(clientKeyExchange.PSKIdentity);
                                        if (psk != null)
                                        {
                                            this._PSKIdentities.AddIdentity(clientKeyExchange.PSKIdentity, psk);
                                        }
                                    }

                                    if (psk != null)
                                    {
                                        var ecKeyExchange = session.Handshake.KeyExchange as ECDHEKeyExchange;
                                        var otherSecret = ecKeyExchange.GetPreMasterSecret(clientKeyExchange.PublicKeyBytes);
                                        preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, psk);

                                    }
                                }
                            }
                            else if (session.Handshake.KeyExchange.KeyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                            {
                                var clientKeyExchange = PSKClientKeyExchange.Deserialise(stream);
                                if (clientKeyExchange != null)
                                {
                                    session.PSKIdentity = Encoding.UTF8.GetString(clientKeyExchange.PSKIdentity);
                                    var psk = this._PSKIdentities.GetKey(clientKeyExchange.PSKIdentity);

                                    if (psk == null)
                                    {
                                        psk = this._ValidatePSK(clientKeyExchange.PSKIdentity);
                                        if (psk != null)
                                        {
                                            this._PSKIdentities.AddIdentity(clientKeyExchange.PSKIdentity, psk);
                                        }
                                    }

                                    if (psk != null)
                                    {
                                        var ecKeyExchange = session.Handshake.KeyExchange as ECDHEKeyExchange;
                                        var otherSecret = new byte[psk.Length];
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
                            break;
                        }
                    case THandshakeType.Finished:
                        {
                            var finished = Finished.Deserialise(stream);
                            if (session == null)
                            {
                                break;
                            }

                            var handshakeHash = session.Handshake.GetHash(session.Version);
                            var calculatedVerifyData = TLSUtils.GetVerifyData(session.Version, session.Handshake, false, true, handshakeHash);
                            if (!finished.VerifyData.SequenceEqual(calculatedVerifyData))
                            {
                                throw new Exception();
                            }

                            this.SendChangeCipherSpec(session);
                            session.Handshake.UpdateHandshakeHash(data);
                            handshakeHash = session.Handshake.GetHash(session.Version);
                            var serverFinished = new Finished
                            {
                                VerifyData = TLSUtils.GetVerifyData(session.Version, session.Handshake, false, false, handshakeHash)
                            };
                            this.SendResponse(session, serverFinished, session.Handshake.MessageSequence);
                            session.Handshake.MessageSequence++;
                            break;
                        }
                    default:
                        break;
                }
            }
        }

		private void SendResponse(Session session, IHandshakeMessage handshakeMessage, ushort messageSequence)
		{
            if(session == null)
            {
                throw new ArgumentNullException(nameof(session));
            }

            if(handshakeMessage == null)
            {
                throw new ArgumentNullException(nameof(handshakeMessage));
            }

			var size = handshakeMessage.CalculateSize(session.Version);
			var maxPayloadSize = this._MaxPacketSize - DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD;
			if (size > maxPayloadSize)
			{
                //fragments
                return;
			}

            var record = new DTLSRecord
            {
                RecordType = TRecordType.Handshake,
                Epoch = session.Epoch,
                SequenceNumber = session.NextSequenceNumber(),
                Fragment = new byte[HandshakeRecord.RECORD_OVERHEAD + size]
            };

            if (session.Version != null)
            {
                record.Version = session.Version;
            }

            var handshakeRecord = new HandshakeRecord
            {
                MessageType = handshakeMessage.MessageType,
                MessageSeq = messageSequence,
                Length = (uint)size,
                FragmentLength = (uint)size
            };

            using (var stream = new MemoryStream(record.Fragment))
			{
				handshakeRecord.Serialise(stream);
				handshakeMessage.Serialise(stream, session.Version);
			}

            if (handshakeMessage.MessageType != THandshakeType.HelloVerifyRequest)
            {
                session.Handshake.UpdateHandshakeHash(record.Fragment);
            }

            var responseSize = DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD + size;
            if (session.Cipher != null)
            {
                var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;                   
                record.Fragment = session.Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
                responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
            }

            var response = new byte[responseSize];
			using (var stream = new MemoryStream(response))
			{
				record.Serialise(stream);
			}
            var parameters = new SocketAsyncEventArgs()
            {
                RemoteEndPoint = session.RemoteEndPoint
            };
            parameters.SetBuffer(response, 0, responseSize);
            this._Socket.SendToAsync(parameters);
		}

		private void SendResponseEnd(Session session, IHandshakeMessage handshakeMessage, ushort messageSequence)
		{
            if(session == null)
            {
                throw new ArgumentNullException(nameof(session));
            }

            if(handshakeMessage == null)
            {
                throw new ArgumentNullException(nameof(handshakeMessage));
            }

			var size = handshakeMessage.CalculateSize(session.Version);
			var maxPayloadSize = this._MaxPacketSize - DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD;
			if (size > maxPayloadSize)
			{
                //fragments
                return;
			}

			var record = this.CreateRecord(session, handshakeMessage, messageSequence);
			session.Handshake.MessageSequence++;
			var recordEnd = this.CreateRecord(session, new ServerHelloDone(), session.Handshake.MessageSequence);
			session.Handshake.MessageSequence++;
			var responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length + DTLSRecord.RECORD_OVERHEAD + recordEnd.Fragment.Length;

			var response = new byte[responseSize];
			using (var stream = new MemoryStream(response))
			{
				record.Serialise(stream);
				recordEnd.Serialise(stream);
			}
            var parameters = new SocketAsyncEventArgs()
            {
                RemoteEndPoint = session.RemoteEndPoint
            };
            parameters.SetBuffer(response, 0, responseSize);
            this._Socket.SendToAsync(parameters);
		}

		private DTLSRecord CreateRecord(Session session, IHandshakeMessage handshakeMessage, ushort messageSequence)
		{
            if (session == null)
            {
                throw new ArgumentNullException(nameof(session));
            }

            if (handshakeMessage == null)
            {
                throw new ArgumentNullException(nameof(handshakeMessage));
            }

            var size = handshakeMessage.CalculateSize(session.Version);
            var record = new DTLSRecord
            {
                RecordType = TRecordType.Handshake,
                Epoch = session.Epoch,
                SequenceNumber = session.NextSequenceNumber(),
                Fragment = new byte[HandshakeRecord.RECORD_OVERHEAD + size]
            };

            if (session.Version != null)
            {
                record.Version = session.Version;
            }

            var handshakeRecord = new HandshakeRecord
            {
                MessageType = handshakeMessage.MessageType,
                MessageSeq = messageSequence,
                Length = (uint)size,
                FragmentLength = (uint)size
            };

            using (var stream = new MemoryStream(record.Fragment))
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
				var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
				record.Fragment = session.Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
			}

			return record;
		}


		private void SendChangeCipherSpec(Session session)
		{
            if (session == null)
            {
                throw new ArgumentNullException(nameof(session));
            }

            var size = 1;
			var responseSize = DTLSRecord.RECORD_OVERHEAD + size;
			var response = new byte[responseSize];
            var record = new DTLSRecord
            {
                RecordType = TRecordType.ChangeCipherSpec,
                Epoch = session.Epoch,
                SequenceNumber = session.NextSequenceNumber(),
                Fragment = new byte[size]
            };
            record.Fragment[0] = 1;
			if (session.Version != null)
            {
                record.Version = session.Version;
            }

            using (var stream = new MemoryStream(response))
			{
				record.Serialise(stream);
			}
            var parameters = new SocketAsyncEventArgs()
            {
                RemoteEndPoint = session.RemoteEndPoint
            };
            parameters.SetBuffer(response, 0, responseSize);
            this._Socket.SendToAsync(parameters);
            session.ChangeEpoch();
		}
	}
}