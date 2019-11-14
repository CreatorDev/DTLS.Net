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

using DTLS.Net;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Utilities.IO.Pem;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;

namespace DTLS
{
    public class Client
    {
        public delegate void DataReceivedEventHandler(EndPoint endPoint, byte[] data);
        public event DataReceivedEventHandler DataReceived;

        private const int MAXPACKETSIZE = 1440;

        private static readonly Version _SupportedVersion = DTLSRecord.Version1_0;
        private readonly ManualResetEvent _TriggerProcessRecords = new ManualResetEvent(false);
        private readonly ManualResetEvent _Connected = new ManualResetEvent(false);
        private readonly HandshakeInfo _HandshakeInfo = new HandshakeInfo();
        private readonly DTLSRecords _Records = new DTLSRecords();
        private readonly List<byte[]> _FragmentedRecordList = new List<byte[]>();

        private Socket _Socket;
        private bool _Terminate;
        private Thread _ProcessRecordsThread;
        private EndPoint _ServerEndPoint;
        private ushort? _ServerEpoch;
        private long _ServerSequenceNumber;
        private ushort? _EncyptedServerEpoch;
        private byte[] _ServerCertificate;
        private ushort _Epoch;
        private ushort _MessageSequence;
        private TlsCipher _Cipher;
        private Version _Version;
        private bool _SendCertificate;
        private IHandshakeMessage _ClientKeyExchange;
        private Certificate _Certificate;
        private AsymmetricKeyParameter _PrivateKey;
        private RSACryptoServiceProvider _PrivateKeyRsa;
        private bool _IsFragment = false;
        private PSKIdentity _PSKIdentity;

        private long _SequenceNumber = -1; //realy only 48 bit

        public EndPoint LocalEndPoint { get; }

        public PSKIdentities PSKIdentities { get; }

        public List<TCipherSuite> SupportedCipherSuites { get; }

        public RSACryptoServiceProvider PublicKey { get; set; }

        public Client(EndPoint localEndPoint)
            : this(localEndPoint, new List<TCipherSuite>()) => this.SupportedCipherSuites = new List<TCipherSuite>();

        public Client(EndPoint localEndPoint, List<TCipherSuite> supportedCipherSuites)
        {
            this.LocalEndPoint = localEndPoint ?? throw new ArgumentNullException(nameof(localEndPoint));
            this.SupportedCipherSuites = supportedCipherSuites;
            this.PSKIdentities = new PSKIdentities();
            this._HandshakeInfo.ClientRandom = new RandomData();
            this._HandshakeInfo.ClientRandom.Generate();
        }
        
        private void ChangeEpoch()
        {
            ++this._Epoch;
            this._SequenceNumber = -1;
        }

        private long NextSequenceNumber() => ++this._SequenceNumber;

        private void ProcessHandshake(DTLSRecord record)
        {
            if(record == null)
            {
                throw new ArgumentNullException(nameof(record));
            }

            var data = record.Fragment;
            if (this._EncyptedServerEpoch == record.Epoch)
            {
                var count = 0;
                while ((this._Cipher == null) && (count < 500))
                {
                    Thread.Sleep(10);
                    count++;
                }

                if (this._Cipher == null)
                {
                    throw new Exception("Need Cipher for Encrypted Session");
                }
                
                var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                data = this._Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
            }
            
            using (var tempStream = new MemoryStream(data))
            {
                var handshakeRec = HandshakeRecord.Deserialise(tempStream);
                if (handshakeRec.Length > (handshakeRec.FragmentLength + handshakeRec.FragmentOffset))
                {
                    this._IsFragment = true;
                    this._FragmentedRecordList.Add(data);
                    return;
                }
                else if (this._IsFragment)
                {
                    this._FragmentedRecordList.Add(data);
                    data = new byte[0];
                    foreach (var rec in this._FragmentedRecordList)
                    {
                        data = data.Concat(rec.Skip(HandshakeRecord.RECORD_OVERHEAD)).ToArray();
                    }

                    var tempHandshakeRec = new HandshakeRecord()
                    {
                        Length = handshakeRec.Length,
                        MessageSeq = handshakeRec.MessageSeq,
                        MessageType = handshakeRec.MessageType,
                        FragmentLength = handshakeRec.Length,
                        FragmentOffset = 0
                    };

                    var tempHandshakeBytes = new byte[HandshakeRecord.RECORD_OVERHEAD];
                    using (var updateStream = new MemoryStream(tempHandshakeBytes))
                    {
                        tempHandshakeRec.Serialise(updateStream);
                    }

                    data = tempHandshakeBytes.Concat(data).ToArray();
                }
            }

            using (var stream = new MemoryStream(data))
            {
                var handshakeRecord = HandshakeRecord.Deserialise(stream);
                Console.WriteLine(handshakeRecord.MessageType.ToString());
                switch (handshakeRecord.MessageType)
                {
                    case THandshakeType.HelloRequest:
                        {
                            break;
                        }
                    case THandshakeType.ClientHello:
                        {
                            break;
                        }
                    case THandshakeType.ServerHello:
                        {
                            var serverHello = ServerHello.Deserialise(stream);
                            this._HandshakeInfo.UpdateHandshakeHash(data);
                            this._ServerEpoch = record.Epoch;
                            this._HandshakeInfo.CipherSuite = (TCipherSuite)serverHello.CipherSuite;
                            this._HandshakeInfo.ServerRandom = serverHello.Random;
                            this._Version = serverHello.ServerVersion < this._Version ? serverHello.ServerVersion : _SupportedVersion;
                            break;
                        }
                    case THandshakeType.HelloVerifyRequest:
                        {
                            var helloVerifyRequest = HelloVerifyRequest.Deserialise(stream);
                            this._Version = helloVerifyRequest.ServerVersion;
                            this.SendHello(helloVerifyRequest.Cookie);
                            break;
                        }
                    case THandshakeType.Certificate:
                        {
                            var cert = Certificate.Deserialise(stream, TCertificateType.X509);
                            this._HandshakeInfo.UpdateHandshakeHash(data);
                            this._ServerCertificate = cert.Cert;
                            break;
                        }
                    case THandshakeType.ServerKeyExchange:
                        {
                            this._HandshakeInfo.UpdateHandshakeHash(data);
                            var keyExchangeAlgorithm = CipherSuites.GetKeyExchangeAlgorithm(this._HandshakeInfo.CipherSuite);
                            byte[] preMasterSecret = null;
                            IKeyExchange keyExchange = null;
                            if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_ECDSA)
                            {
                                var serverKeyExchange = ECDHEServerKeyExchange.Deserialise(stream, this._Version);
                                var keyExchangeECDHE = new ECDHEKeyExchange
                                {
                                    CipherSuite = this._HandshakeInfo.CipherSuite,
                                    Curve = serverKeyExchange.EllipticCurve,
                                    KeyExchangeAlgorithm = keyExchangeAlgorithm,
                                    ClientRandom = this._HandshakeInfo.ClientRandom,
                                    ServerRandom = this._HandshakeInfo.ServerRandom
                                };
                                keyExchangeECDHE.GenerateEphemeralKey();
                                var clientKeyExchange = new ECDHEClientKeyExchange(keyExchangeECDHE.PublicKey);
                                this._ClientKeyExchange = clientKeyExchange;
                                preMasterSecret = keyExchangeECDHE.GetPreMasterSecret(serverKeyExchange.PublicKeyBytes);
                                keyExchange = keyExchangeECDHE;
                            }
                            else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_PSK)
                            {
                                var serverKeyExchange = ECDHEPSKServerKeyExchange.Deserialise(stream);
                                var keyExchangeECDHE = new ECDHEKeyExchange
                                {
                                    CipherSuite = this._HandshakeInfo.CipherSuite,
                                    Curve = serverKeyExchange.EllipticCurve,
                                    KeyExchangeAlgorithm = keyExchangeAlgorithm,
                                    ClientRandom = this._HandshakeInfo.ClientRandom,
                                    ServerRandom = this._HandshakeInfo.ServerRandom
                                };
                                keyExchangeECDHE.GenerateEphemeralKey();
                                var clientKeyExchange = new ECDHEPSKClientKeyExchange(keyExchangeECDHE.PublicKey);
                                if (serverKeyExchange.PSKIdentityHint != null)
                                {
                                    var key = this.PSKIdentities.GetKey(serverKeyExchange.PSKIdentityHint);
                                    if (key != null)
                                    {
                                        this._PSKIdentity = new PSKIdentity() { Identity = serverKeyExchange.PSKIdentityHint, Key = key };
                                    }
                                }
                                if (this._PSKIdentity == null)
                                {
                                    this._PSKIdentity = this.PSKIdentities.GetRandom();
                                }

                                clientKeyExchange.PSKIdentity = this._PSKIdentity.Identity;
                                this._ClientKeyExchange = clientKeyExchange;
                                var otherSecret = keyExchangeECDHE.GetPreMasterSecret(serverKeyExchange.PublicKeyBytes);
                                preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, this._PSKIdentity.Key);
                                keyExchange = keyExchangeECDHE;
                            }
                            else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                            {
                                var serverKeyExchange = PSKServerKeyExchange.Deserialise(stream);
                                var clientKeyExchange = new PSKClientKeyExchange();
                                if (serverKeyExchange.PSKIdentityHint != null)
                                {
                                    var key = this.PSKIdentities.GetKey(serverKeyExchange.PSKIdentityHint);
                                    if (key != null)
                                    {
                                        this._PSKIdentity = new PSKIdentity() { Identity = serverKeyExchange.PSKIdentityHint, Key = key };
                                    }
                                }
                                if (this._PSKIdentity == null)
                                {
                                    this._PSKIdentity = this.PSKIdentities.GetRandom();
                                }

                                var otherSecret = new byte[this._PSKIdentity.Key.Length];
                                clientKeyExchange.PSKIdentity = this._PSKIdentity.Identity;
                                this._ClientKeyExchange = clientKeyExchange;
                                preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, this._PSKIdentity.Key);
                            }
                            this._Cipher = TLSUtils.AssignCipher(preMasterSecret, true, this._Version, this._HandshakeInfo);
                            break;
                        }
                    case THandshakeType.CertificateRequest:
                        {
                            this._HandshakeInfo.UpdateHandshakeHash(data);
                            this._SendCertificate = true;
                            break;
                        }
                    case THandshakeType.ServerHelloDone:
                        {
                            this._HandshakeInfo.UpdateHandshakeHash(data);
                            var keyExchangeAlgorithm = CipherSuites.GetKeyExchangeAlgorithm(this._HandshakeInfo.CipherSuite);
                            if (this._Cipher == null)
                            {
                                if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                                {
                                    var clientKeyExchange = new PSKClientKeyExchange();
                                    this._PSKIdentity = this.PSKIdentities.GetRandom();
                                    var otherSecret = new byte[this._PSKIdentity.Key.Length];
                                    clientKeyExchange.PSKIdentity = this._PSKIdentity.Identity;
                                    this._ClientKeyExchange = clientKeyExchange;
                                    var preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, this._PSKIdentity.Key);
                                    this._Cipher = TLSUtils.AssignCipher(preMasterSecret, true, this._Version, this._HandshakeInfo);
                                }
                                else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.RSA)
                                {
                                    var clientKeyExchange = new RSAClientKeyExchange();
                                    this._ClientKeyExchange = clientKeyExchange;
                                    var PreMasterSecret = TLSUtils.GetRsaPreMasterSecret(_SupportedVersion);
                                    clientKeyExchange.PremasterSecret = TLSUtils.GetEncryptedRsaPreMasterSecret(this._ServerCertificate, PreMasterSecret);
                                    this._Cipher = TLSUtils.AssignCipher(PreMasterSecret, true, this._Version, this._HandshakeInfo);
                                }
                                else
                                {
                                    throw new NotImplementedException($"Key Exchange Algorithm {keyExchangeAlgorithm} Not Implemented");
                                }
                            }

                            if (this._SendCertificate)
                            {
                                this.SendHandshakeMessage(this._Certificate, false);
                            }

                            this.SendHandshakeMessage(this._ClientKeyExchange, false);

                            if (this._SendCertificate)
                            {
                                var signatureHashAlgorithm = new SignatureHashAlgorithm() { Signature = TSignatureAlgorithm.ECDSA, Hash = THashAlgorithm.SHA256 };
                                if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.RSA)
                                {
                                    signatureHashAlgorithm = new SignatureHashAlgorithm() { Signature = TSignatureAlgorithm.RSA, Hash = THashAlgorithm.SHA1 };
                                }

                                var certVerify = new CertificateVerify
                                {
                                    SignatureHashAlgorithm = signatureHashAlgorithm,
                                    Signature = TLSUtils.Sign(this._PrivateKey, this._PrivateKeyRsa, true, this._Version, this._HandshakeInfo, signatureHashAlgorithm, this._HandshakeInfo.GetHash(this._Version))
                                };

                                this.SendHandshakeMessage(certVerify, false);
                            }

                            this.SendChangeCipherSpec();
                            var handshakeHash = this._HandshakeInfo.GetHash(this._Version);
                            var finished = new Finished
                            {
                                VerifyData = TLSUtils.GetVerifyData(this._Version, this._HandshakeInfo, true, true, handshakeHash)
                            };

                            this.SendHandshakeMessage(finished, true);
#if DEBUG
                            Console.Write("Handshake Hash:");
                            TLSUtils.WriteToConsole(handshakeHash);
                            Console.Write("Sent Verify:");
                            TLSUtils.WriteToConsole(finished.VerifyData);
#endif
                            break;
                        }
                    case THandshakeType.NewSessionTicket:
                        {
                            this._HandshakeInfo.UpdateHandshakeHash(data);
                            break;
                        }
                    case THandshakeType.CertificateVerify:
                        {
                            break;
                        }
                    case THandshakeType.ClientKeyExchange:
                        {
                            break;
                        }
                    case THandshakeType.Finished:
                        {
                            var serverFinished = Finished.Deserialise(stream);
                            var handshakeHash = this._HandshakeInfo.GetHash(this._Version);
                            var calculatedVerifyData = TLSUtils.GetVerifyData(this._Version, this._HandshakeInfo, true, false, handshakeHash);

                            Console.Write("Recieved Verify:");
                            TLSUtils.WriteToConsole(serverFinished.VerifyData);
                            Console.Write("Calc Verify:");
                            TLSUtils.WriteToConsole(calculatedVerifyData);
                            if (serverFinished.VerifyData.SequenceEqual(calculatedVerifyData))
                            {
                                Console.WriteLine("Handshake Complete");
                                this._Connected.Set();
                            }
                            break;
                        }
                    default:
                        {
                            break;
                        }
                }
            }

            this._IsFragment = false;
            this._FragmentedRecordList.RemoveAll(x => true);
        }

        private void ProcessRecord(DTLSRecord record)
        {
            try
            {
                Console.WriteLine(record.RecordType.ToString());
                switch (record.RecordType)
                {
                    case TRecordType.ChangeCipherSpec:
                        {
                            if (this._ServerEpoch.HasValue)
                            {
                                this._ServerEpoch++;
                                this._ServerSequenceNumber = 0;
                                this._EncyptedServerEpoch = this._ServerEpoch;
                            }
                            break;
                        }
                    case TRecordType.Alert:
                        {
                            AlertRecord alertRecord;
                            try
                            {
                                if ((this._Cipher == null) || (!this._EncyptedServerEpoch.HasValue))
                                {
                                    alertRecord = AlertRecord.Deserialise(record.Fragment);
                                }
                                else
                                {
                                    var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                                    var data = this._Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.Alert, record.Fragment, 0, record.Fragment.Length);
                                    alertRecord = AlertRecord.Deserialise(data);
                                }
                            }
                            catch
                            {
                                alertRecord = new AlertRecord
                                {
                                    AlertLevel = TAlertLevel.Fatal
                                };
                            }
                            if (alertRecord.AlertLevel == TAlertLevel.Fatal)
                            {
                                this._Connected.Set();
                            }
                            else if ((alertRecord.AlertLevel == TAlertLevel.Warning) || (alertRecord.AlertDescription == TAlertDescription.CloseNotify))
                            {
                                if (alertRecord.AlertDescription == TAlertDescription.CloseNotify)
                                {
                                    this.SendAlert(TAlertLevel.Warning, TAlertDescription.CloseNotify);
                                    this._Connected.Set();
                                }
                            }
                            break;
                        }
                    case TRecordType.Handshake:
                        {
                            this.ProcessHandshake(record);
                            this._ServerSequenceNumber = record.SequenceNumber + 1;
                            break;
                        }
                    case TRecordType.ApplicationData:
                        {
                            if (this._Cipher != null)
                            {
                                var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                                var data = this._Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.ApplicationData, record.Fragment, 0, record.Fragment.Length);
                                DataReceived?.Invoke(record.RemoteEndPoint, data);
                            }
                            this._ServerSequenceNumber = record.SequenceNumber + 1;
                            break;
                        }
                    default:
                        break;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        private void ProcessRecords()
        {
            while (!this._Terminate)
            {
                this._TriggerProcessRecords.Reset();
                var record = this._Records.PeekRecord();
                while (record != null)
                {
                    if (this._ServerEpoch.HasValue)
                    {
                        if ((this._ServerSequenceNumber == record.SequenceNumber) && (this._ServerEpoch == record.Epoch))
                        {
                            this._Records.RemoveRecord();
                            this.ProcessRecord(record);
                            record = this._Records.PeekRecord();
                        }
                        else
                        {
                            record = null;
                        }
                    }
                    else
                    {
                        this._Records.RemoveRecord();
                        this.ProcessRecord(record);
                        record = this._Records.PeekRecord();
                    }
                }
                if (!this._Terminate)
                {
                    this._TriggerProcessRecords.WaitOne();
                }
            }
        }

        private void ReceiveCallback(object sender, SocketAsyncEventArgs e)
        {
            if (e.BytesTransferred == 0)
            {
                //do nothing?
                return;
            }

            var count = e.BytesTransferred;
            var data = new byte[count];
            Buffer.BlockCopy(e.Buffer, 0, data, 0, count);
            var stream = new MemoryStream(data);
            while (stream.Position < stream.Length)
            {
                var record = DTLSRecord.Deserialise(stream);
                record.RemoteEndPoint = e.RemoteEndPoint;
                this._Records.Add(record);
                this._TriggerProcessRecords.Set();
            }

            if (sender is Socket socket)
            {
                var remoteEndPoint = socket.AddressFamily == AddressFamily.InterNetwork ? new IPEndPoint(IPAddress.Any, 0) : (EndPoint)new IPEndPoint(IPAddress.IPv6Any, 0);
                e.RemoteEndPoint = remoteEndPoint;
                e.SetBuffer(0, 4096);
                socket.ReceiveFromAsync(e);
            }
        }

        private Socket SetupSocket(AddressFamily addressFamily)
        {
            var result = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (addressFamily == AddressFamily.InterNetworkV6)
            {
                result.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
            }

            if (Environment.OSVersion.Platform != PlatformID.Unix)
            {
                // do not throw SocketError.ConnectionReset by ignoring ICMP Port Unreachable
                const int SIO_UDP_CONNRESET = -1744830452;
                result.IOControl(SIO_UDP_CONNRESET, new byte[] { 0 }, null);
            }
            return result;
        }


        public void Send(byte[] data)
        {
            if(this._Socket == null)
            {
                throw new Exception("Socket cannot be null");
            }

            try
            {
                var record = new DTLSRecord
                {
                    RecordType = TRecordType.ApplicationData,
                    Epoch = _Epoch,
                    SequenceNumber = this.NextSequenceNumber()
                };

                if (this._Version != null)
                {
                    record.Version = this._Version;
                }

                var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                record.Fragment = this._Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.ApplicationData, data, 0, data.Length);

                var responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                var response = new byte[responseSize];
                using (var stream = new MemoryStream(response))
                {
                    record.Serialise(stream);
                }

                var parameters = new SocketAsyncEventArgs()
                {
                    RemoteEndPoint = _ServerEndPoint
                };

                parameters.SetBuffer(response, 0, responseSize);
                this._Socket.SendToAsync(parameters);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }

        private void SendAlert(TAlertLevel alertLevel, TAlertDescription alertDescription)
        {
            var record = new DTLSRecord
            {
                RecordType = TRecordType.Alert,
                Epoch = _Epoch,
                SequenceNumber = this.NextSequenceNumber()
            };

            if (this._Version != null)
            {
                record.Version = this._Version;
            }

            var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;

            var data = new byte[2];
            data[0] = (byte)alertLevel;
            data[1] = (byte)alertDescription;
            record.Fragment = this._Cipher == null ? data : this._Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.ApplicationData, data, 0, data.Length);
            var responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
            var response = new byte[responseSize];
            using (var stream = new MemoryStream(response))
            {
                record.Serialise(stream);
            }
            var parameters = new SocketAsyncEventArgs()
            {
                RemoteEndPoint = _ServerEndPoint
            };
            parameters.SetBuffer(response, 0, responseSize);
            this._Socket.SendToAsync(parameters);
        }

        private void SendChangeCipherSpec()
        {
            var message = this.GetChangeCipherSpec();
            var parameters = new SocketAsyncEventArgs()
            {
                RemoteEndPoint = _ServerEndPoint
            };

            parameters.SetBuffer(message, 0, message.Length);
            this._Socket.SendToAsync(parameters);
            this.ChangeEpoch();
        }

        private byte[] GetChangeCipherSpec()
        {
            var size = 1;
            var responseSize = DTLSRecord.RECORD_OVERHEAD + size;
            var response = new byte[responseSize];
            var record = new DTLSRecord
            {
                RecordType = TRecordType.ChangeCipherSpec,
                Epoch = _Epoch,
                SequenceNumber = this.NextSequenceNumber(),
                Fragment = new byte[size]
            };

            record.Fragment[0] = 1;
            if (this._Version != null)
            {
                record.Version = this._Version;
            }

            using (var stream = new MemoryStream(response))
            {
                record.Serialise(stream);
            }
            return response;
        }

        private byte[] GetBytes(IHandshakeMessage handshakeMessage, bool encrypt)
        {
            var size = handshakeMessage.CalculateSize(this._Version);
            var maxPayloadSize = MAXPACKETSIZE - DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD;

            if (size > maxPayloadSize)
            {
                var wholeMessage = new byte[0];

                var record = new DTLSRecord
                {
                    RecordType = TRecordType.Handshake,
                    Epoch = _Epoch
                };
                if (this._Version != null)
                {
                    record.Version = this._Version;
                }

                var handshakeRecord = new HandshakeRecord
                {
                    MessageType = handshakeMessage.MessageType,
                    MessageSeq = _MessageSequence
                };

                if (!(handshakeMessage.MessageType == THandshakeType.HelloVerifyRequest
                   || (handshakeMessage.MessageType == THandshakeType.ClientHello && (handshakeMessage as ClientHello).Cookie == null)))
                {
                    record.Fragment = new byte[HandshakeRecord.RECORD_OVERHEAD + size];
                    handshakeRecord.Length = (uint)size;
                    handshakeRecord.FragmentLength = (uint)size;
                    handshakeRecord.FragmentOffset = 0u;
                    using (var stream = new MemoryStream(record.Fragment))
                    {
                        handshakeRecord.Serialise(stream);
                        handshakeMessage.Serialise(stream, this._Version);
                    }

                    this._HandshakeInfo.UpdateHandshakeHash(record.Fragment);
                }

                var dataMessage = new byte[size];
                using (var stream = new MemoryStream(dataMessage))
                {
                    handshakeMessage.Serialise(stream, this._Version);
                }

                var dataMessageFragments = dataMessage.ChunkBySize(maxPayloadSize);
                handshakeRecord.FragmentOffset = 0U;
                dataMessageFragments.ForEach(x =>
                {
                    handshakeRecord.Length = (uint)size;
                    handshakeRecord.FragmentLength = (uint)x.Count();
                    record.SequenceNumber = this.NextSequenceNumber();

                    var baseMessage = new byte[HandshakeRecord.RECORD_OVERHEAD];
                    using (var stream = new MemoryStream(baseMessage))
                    {
                        handshakeRecord.Serialise(stream);
                    }

                    record.Fragment = baseMessage.Concat(x).ToArray();

                    var responseSize = DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD + x.Count();
                    if ((this._Cipher != null) && encrypt)
                    {
                        var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                        record.Fragment = this._Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
                        responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                    }
                    var response = new byte[responseSize];
                    using (var stream = new MemoryStream(response))
                    {
                        record.Serialise(stream);
                    }

                    wholeMessage = wholeMessage.Concat(response).ToArray();
                    handshakeRecord.FragmentOffset += (uint)x.Count();
                });

                this._MessageSequence++;
                return wholeMessage;
            }
            else
            {
                var record = new DTLSRecord
                {
                    RecordType = TRecordType.Handshake,
                    Epoch = _Epoch,
                    SequenceNumber = this.NextSequenceNumber(),
                    Fragment = new byte[HandshakeRecord.RECORD_OVERHEAD + size]
                };
                if (this._Version != null)
                {
                    record.Version = this._Version;
                }

                var handshakeRecord = new HandshakeRecord
                {
                    MessageType = handshakeMessage.MessageType,
                    MessageSeq = _MessageSequence
                };
                this._MessageSequence++;
                handshakeRecord.Length = (uint)size;
                handshakeRecord.FragmentLength = (uint)size;
                using (var stream = new MemoryStream(record.Fragment))
                {
                    handshakeRecord.Serialise(stream);
                    handshakeMessage.Serialise(stream, this._Version);
                }

                if (!(handshakeMessage.MessageType == THandshakeType.HelloVerifyRequest
                   || (handshakeMessage.MessageType == THandshakeType.ClientHello && (handshakeMessage as ClientHello).Cookie == null)))
                {
                    this._HandshakeInfo.UpdateHandshakeHash(record.Fragment);
                }

                var responseSize = DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD + size;
                if ((this._Cipher != null) && encrypt)
                {
                    var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                    record.Fragment = this._Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
                    responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                }

                var response = new byte[responseSize];
                using (var stream = new MemoryStream(response))
                {
                    record.Serialise(stream);
                }

                return response;
            }
        }

        private void SendHello(byte[] cookie)
        {
            var clientHello = new ClientHello
            {
                ClientVersion = _SupportedVersion,
                Random = this._HandshakeInfo.ClientRandom,
                Cookie = cookie
            };

            var cipherSuites = new ushort[this.SupportedCipherSuites.Count];
            var index = 0;
            foreach (var item in this.SupportedCipherSuites)
            {
                cipherSuites[index] = (ushort)item;
                index++;
            }
            clientHello.CipherSuites = cipherSuites;
            clientHello.CompressionMethods = new byte[1];
            clientHello.CompressionMethods[0] = 0;

            clientHello.Extensions = new Extensions
            {
                new Extension() { ExtensionType = TExtensionType.SessionTicketTLS },
                //new Extension() { ExtensionType = TExtensionType.EncryptThenMAC },
                //new Extension() { ExtensionType = TExtensionType.ExtendedMasterSecret },
            };

            var ellipticCurvesExtension = new EllipticCurvesExtension();
            for (var curve = 0; curve < (int)TEllipticCurve.secp521r1; curve++)
            {
                if (EllipticCurveFactory.SupportedCurve((TEllipticCurve)curve))
                {
                    ellipticCurvesExtension.SupportedCurves.Add((TEllipticCurve)curve);

                }
            }
            clientHello.Extensions.Add(new Extension(ellipticCurvesExtension));
            var cllipticCurvePointFormatsExtension = new EllipticCurvePointFormatsExtension();
            cllipticCurvePointFormatsExtension.SupportedPointFormats.Add(TEllipticCurvePointFormat.Uncompressed);
            clientHello.Extensions.Add(new Extension(cllipticCurvePointFormatsExtension));
            var signatureAlgorithmsExtension = new SignatureAlgorithmsExtension();
            signatureAlgorithmsExtension.SupportedAlgorithms.Add(new SignatureHashAlgorithm() { Hash = THashAlgorithm.SHA1, Signature = TSignatureAlgorithm.RSA });
            clientHello.Extensions.Add(new Extension(signatureAlgorithmsExtension));
            this.SendHandshakeMessage(clientHello, false);
        }

        private void SendHandshakeMessage(IHandshakeMessage handshakeMessage, bool encrypt)
        {
            var bytes = this.GetBytes(handshakeMessage, encrypt);
            var parameters = new SocketAsyncEventArgs()
            {
                RemoteEndPoint = _ServerEndPoint
            };
            parameters.SetBuffer(bytes, 0, bytes.Length);
            this._Socket.SendToAsync(parameters);
        }

        public void ConnectToServer(EndPoint serverEndPoint)
        {
            this.ConnectToServerAsync(serverEndPoint);
            this._Connected.WaitOne();
        }

        public void ConnectToServerAsync(EndPoint serverEndPoint)
        {
            this._ServerEndPoint = serverEndPoint;
            if (this.SupportedCipherSuites.Count == 0)
            {
                this.SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8); //Test 1.2
                this.SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                this.SupportedCipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8); //Test 1.2
                this.SupportedCipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                this.SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                this.SupportedCipherSuites.Add(TCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            }

            this._Socket = this.SetupSocket(this.LocalEndPoint.AddressFamily);
            this._Socket.Bind(this.LocalEndPoint);
            this._ProcessRecordsThread = new Thread(new ThreadStart(this.ProcessRecords));
            if (this._ProcessRecordsThread.Name == null)
            {
                this._ProcessRecordsThread.Name = "ProcessRecordsThread";
            }

            this._ProcessRecordsThread.IsBackground = true;
            this._ProcessRecordsThread.Start();
            this.StartReceive(this._Socket);
            this.SendHello(null);
        }

        public void LoadX509Certificate(X509Chain chain)
        {
            if (chain == null)
            {
                throw new ArgumentNullException(nameof(chain));
            }

            var mainCert = chain.ChainElements[0].Certificate;

            this._PrivateKeyRsa = (RSACryptoServiceProvider)mainCert.PrivateKey;
            this.PublicKey = (RSACryptoServiceProvider)mainCert.PublicKey.Key;

            this._Certificate = new Certificate
            {
                CertChain = new List<byte[]>() { mainCert.GetRawCertData(), chain.ChainElements[1].Certificate.GetRawCertData() },
                CertificateType = TCertificateType.X509
            };
        }

        public void LoadCertificateFromPem(string filename)
        {
            using (var stream = File.OpenRead(filename))
            {
                this.LoadCertificateFromPem(stream);
            }
        }

        public void LoadCertificateFromPem(Stream stream)
        {
            var chain = new List<byte[]>();
            var reader = new PemReader(new StreamReader(stream));
            var pem = reader.ReadPemObject();

            while (pem != null)
            {
                if (pem.Type.EndsWith("CERTIFICATE"))
                {
                    chain.Add(pem.Content);
                }
                else if (pem.Type.EndsWith("PRIVATE KEY"))
                {
                    this._PrivateKey = Certificates.GetPrivateKeyFromPEM(pem);
                }
                pem = reader.ReadPemObject();
            }
            this._Certificate = new Certificate
            {
                CertChain = chain,
                CertificateType = TCertificateType.X509
            };
        }

        private void StartReceive(Socket socket)
        {
            var parameters = new SocketAsyncEventArgs
            {
                RemoteEndPoint = socket.AddressFamily == AddressFamily.InterNetwork ? new IPEndPoint(IPAddress.Any, 0) : new IPEndPoint(IPAddress.IPv6Any, 0)
            };
            parameters.Completed += new EventHandler<SocketAsyncEventArgs>(this.ReceiveCallback);
            parameters.SetBuffer(new byte[4096], 0, 4096);
            socket.ReceiveFromAsync(parameters);
        }

        public void SetVersion(Version version) => this._Version = version;

        public void Stop()
        {
            if (this._Socket != null)
            {
                this._Terminate = true;
                this._TriggerProcessRecords.Set();
                this.SendAlert(TAlertLevel.Fatal, TAlertDescription.CloseNotify);
                Thread.Sleep(100);
                this._Socket.Dispose();
                this._Socket = null;
            }
        }

    }
}
