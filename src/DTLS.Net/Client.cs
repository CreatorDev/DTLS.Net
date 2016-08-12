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
using System.Net;
using System.Net.Sockets;
using System.IO;
using Org.BouncyCastle.Crypto.Tls;
using Org.BouncyCastle.Crypto;
using System.Threading;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace DTLS
{
    public class Client
    {
        public delegate void DataReceivedEventHandler(System.Net.EndPoint endPoint, byte[] data);
        public event DataReceivedEventHandler DataReceived;

        private static Version SupportedVersion = DTLSRecord.Version1_2;

        private EndPoint _LocalEndPoint;
        private int _MaxPacketSize = 1440; 
        private Socket _Socket;
        private List<TCipherSuite> _SupportedCipherSuites;

        private bool _Terminate;
        private ManualResetEvent _TriggerProcessRecords = new ManualResetEvent(false);
        private Thread _ProcessRecordsThread;


        private ManualResetEvent _Connected = new ManualResetEvent(false);

        private EndPoint _ServerEndPoint;
        private ushort? _ServerEpoch;
        private long _ServerSequenceNumber;
        private ushort? _EncyptedServerEpoch;

        private ushort _Epoch;
        private long _SequenceNumber; //realy only 48 bit
        private ushort _MessageSequence;
        private TlsCipher _Cipher;
        private Version _Version;

        private bool _SendCertificate;
        private IHandshakeMessage _ClientKeyExchange;

        private Certificate _Certificate;
        private Org.BouncyCastle.Crypto.AsymmetricKeyParameter _PrivateKey;

        private HandshakeInfo _HandshakeInfo = new HandshakeInfo();
        private DTLSRecords _Records = new DTLSRecords();

        private PSKIdentity _PSKIdentity;
        private PSKIdentities _PSKIdentities;

        public EndPoint LocalEndPoint
        {
            get { return _LocalEndPoint; }
        }

        public PSKIdentities PSKIdentities
        {
            get { return _PSKIdentities; }
        }

        public List<TCipherSuite> SupportedCipherSuites
        {
            get
            {
                return _SupportedCipherSuites;
            }
        }

        public Client(EndPoint localEndPoint)
            : this(localEndPoint, null)
		{
            _SupportedCipherSuites = new List<TCipherSuite>();
		}

        public Client(EndPoint localEndPoint, List<TCipherSuite> supportedCipherSuites)
        {
            _LocalEndPoint = localEndPoint;
            _PSKIdentities = new PSKIdentities();
            _SupportedCipherSuites = supportedCipherSuites;
            _HandshakeInfo.ClientRandom = new RandomData();
            _HandshakeInfo.ClientRandom.Generate();

        }


        private void ChangeEpoch()
        {
            _Epoch++;
            _SequenceNumber = 0;
        }

        private long NextSequenceNumber()
        {
            long result = _SequenceNumber++;
            return result;
        }

        private void ProcessHandshake(DTLSRecord record)
        {
            byte[] data;
            if (_EncyptedServerEpoch.HasValue && (_EncyptedServerEpoch.Value == record.Epoch))
            {
                while (_Cipher == null)
                    System.Threading.Thread.Sleep(10);

                if (_Cipher != null)
                {
                    long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                    data = _Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
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
                            break;
                        case THandshakeType.ClientHello:
                            break;
                        case THandshakeType.ServerHello:
                            ServerHello serverHello = ServerHello.Deserialise(stream);
                            if (serverHello != null)
                            {
                                _ServerEpoch = record.Epoch;
                                _HandshakeInfo.UpdateHandshakeHash(data);
                                _HandshakeInfo.CipherSuite = (TCipherSuite)serverHello.CipherSuite;
                                _HandshakeInfo.ServerRandom = serverHello.Random;
                                Version version = SupportedVersion;
                                if (serverHello.ServerVersion < version)
                                    version = serverHello.ServerVersion;
                                _Version = version;
                            }
                            break;
                        case THandshakeType.HelloVerifyRequest:
                            HelloVerifyRequest helloVerifyRequest = HelloVerifyRequest.Deserialise(stream);
                            if (helloVerifyRequest != null)
                            {
                                _Version = helloVerifyRequest.ServerVersion;
                                SendHello(helloVerifyRequest.Cookie);
                            }
                            break;
                        case THandshakeType.Certificate:
                            _HandshakeInfo.UpdateHandshakeHash(data);
                            break;
                        case THandshakeType.ServerKeyExchange:
                            _HandshakeInfo.UpdateHandshakeHash(data);
                            TKeyExchangeAlgorithm keyExchangeAlgorithm = CipherSuites.GetKeyExchangeAlgorithm(_HandshakeInfo.CipherSuite);
                            byte[] preMasterSecret = null;
                            IKeyExchange keyExchange = null;
                            if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_ECDSA)
                            {
                                ECDHEServerKeyExchange serverKeyExchange = ECDHEServerKeyExchange.Deserialise(stream, _Version);
                                ECDHEKeyExchange keyExchangeECDHE = new ECDHEKeyExchange();
                                keyExchangeECDHE.CipherSuite = _HandshakeInfo.CipherSuite;
                                keyExchangeECDHE.Curve = serverKeyExchange.EllipticCurve;
                                keyExchangeECDHE.KeyExchangeAlgorithm = keyExchangeAlgorithm;
                                keyExchangeECDHE.ClientRandom = _HandshakeInfo.ClientRandom;
                                keyExchangeECDHE.ServerRandom = _HandshakeInfo.ServerRandom;
                                keyExchangeECDHE.GenerateEphemeralKey();
                                ECDHEClientKeyExchange clientKeyExchange = new ECDHEClientKeyExchange(keyExchangeECDHE.PublicKey);
                                _ClientKeyExchange = clientKeyExchange;
                                preMasterSecret = keyExchangeECDHE.GetPreMasterSecret(serverKeyExchange.PublicKeyBytes);
                                keyExchange = keyExchangeECDHE;
                            }
                            else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_PSK)
                            {
                                ECDHEPSKServerKeyExchange serverKeyExchange = ECDHEPSKServerKeyExchange.Deserialise(stream, _Version);
                                ECDHEKeyExchange keyExchangeECDHE = new ECDHEKeyExchange();
                                keyExchangeECDHE.CipherSuite = _HandshakeInfo.CipherSuite;
                                keyExchangeECDHE.Curve = serverKeyExchange.EllipticCurve;
                                keyExchangeECDHE.KeyExchangeAlgorithm = keyExchangeAlgorithm;
                                keyExchangeECDHE.ClientRandom = _HandshakeInfo.ClientRandom;
                                keyExchangeECDHE.ServerRandom = _HandshakeInfo.ServerRandom;
                                keyExchangeECDHE.GenerateEphemeralKey();
                                ECDHEPSKClientKeyExchange clientKeyExchange = new ECDHEPSKClientKeyExchange(keyExchangeECDHE.PublicKey);
                                if (serverKeyExchange.PSKIdentityHint != null)
                                {
                                    byte[] key = _PSKIdentities.GetKey(serverKeyExchange.PSKIdentityHint);
                                    if (key != null)
                                        _PSKIdentity = new PSKIdentity() { Identity = serverKeyExchange.PSKIdentityHint, Key = key };
                                }
                                if (_PSKIdentity == null)
                                    _PSKIdentity = _PSKIdentities.GetRandom();
                                clientKeyExchange.PSKIdentity = _PSKIdentity.Identity;
                                _ClientKeyExchange = clientKeyExchange;
                                byte[] otherSecret = keyExchangeECDHE.GetPreMasterSecret(serverKeyExchange.PublicKeyBytes);
                                preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, _PSKIdentity.Key);
                                keyExchange = keyExchangeECDHE;
                            }
                            else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                            {
                                PSKServerKeyExchange serverKeyExchange = PSKServerKeyExchange.Deserialise(stream, _Version);
                                PSKClientKeyExchange clientKeyExchange = new PSKClientKeyExchange();
                                if (serverKeyExchange.PSKIdentityHint != null)
                                {
                                    byte[] key = _PSKIdentities.GetKey(serverKeyExchange.PSKIdentityHint);
                                    if (key != null)
                                        _PSKIdentity = new PSKIdentity() { Identity = serverKeyExchange.PSKIdentityHint, Key = key };
                                }
                                if (_PSKIdentity == null)
                                    _PSKIdentity = _PSKIdentities.GetRandom();
                                byte[] otherSecret = new byte[_PSKIdentity.Key.Length];
                                clientKeyExchange.PSKIdentity = _PSKIdentity.Identity;
                                _ClientKeyExchange = clientKeyExchange;
                                preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, _PSKIdentity.Key);
                            }
                            _Cipher = TLSUtils.AssignCipher(preMasterSecret, true, _Version, _HandshakeInfo);

                            break;
                        case THandshakeType.CertificateRequest:
                            _HandshakeInfo.UpdateHandshakeHash(data);
                            _SendCertificate = true;
                            break;
                        case THandshakeType.ServerHelloDone:
                            _HandshakeInfo.UpdateHandshakeHash(data);
                            if (_Cipher == null)
                            {
                                keyExchangeAlgorithm = CipherSuites.GetKeyExchangeAlgorithm(_HandshakeInfo.CipherSuite);
                                if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                                {
                                    PSKClientKeyExchange clientKeyExchange = new PSKClientKeyExchange();
                                    _PSKIdentity = _PSKIdentities.GetRandom();
                                    byte[] otherSecret = new byte[_PSKIdentity.Key.Length];
                                    clientKeyExchange.PSKIdentity = _PSKIdentity.Identity;
                                    _ClientKeyExchange = clientKeyExchange;
                                    preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, _PSKIdentity.Key);
                                    _Cipher = TLSUtils.AssignCipher(preMasterSecret, true, _Version, _HandshakeInfo);
                                }
                            }

                            if (_SendCertificate)
                            {
                                SendHandshakeMessage(_Certificate, false);
                            }
                            SendHandshakeMessage(_ClientKeyExchange, false);
                            if (_SendCertificate)
                            {
                                CertificateVerify certificateVerify = new CertificateVerify();
                                byte[] signatureHash = _HandshakeInfo.GetHash();
                                certificateVerify.SignatureHashAlgorithm = new SignatureHashAlgorithm() { Signature = TSignatureAlgorithm.ECDSA, Hash = THashAlgorithm.SHA256 };
                                certificateVerify.Signature = TLSUtils.Sign(_PrivateKey, true, _Version, _HandshakeInfo, certificateVerify.SignatureHashAlgorithm, signatureHash);
                                SendHandshakeMessage(certificateVerify, false);
                            }
                            SendChangeCipherSpec();
                            byte[] handshakeHash = _HandshakeInfo.GetHash();
                            Finished finished = new Finished();
                            finished.VerifyData = TLSUtils.GetVerifyData(_Version,_HandshakeInfo,true, true, handshakeHash);
                            SendHandshakeMessage(finished, true);
#if DEBUG
                            Console.Write("Handshake Hash:");
                            TLSUtils.WriteToConsole(handshakeHash);
                            Console.Write("Sent Verify:");
                            TLSUtils.WriteToConsole(finished.VerifyData);
#endif
                            break;
                        case THandshakeType.CertificateVerify:
                            break;
                        case THandshakeType.ClientKeyExchange:
                            break;
                        case THandshakeType.Finished:
                            Finished serverFinished = Finished.Deserialise(stream);
                            handshakeHash = _HandshakeInfo.GetHash();
                            byte[] calculatedVerifyData = TLSUtils.GetVerifyData(_Version,_HandshakeInfo, true, false, handshakeHash);
#if DEBUG
                            Console.Write("Recieved Verify:");
                            TLSUtils.WriteToConsole(serverFinished.VerifyData);
                            Console.Write("Calc Verify:");
                            TLSUtils.WriteToConsole(calculatedVerifyData);
#endif
                            if (TLSUtils.ByteArrayCompare(serverFinished.VerifyData, calculatedVerifyData))
                            {
#if DEBUG
                                Console.WriteLine("Handshake Complete");
#endif
                                _Connected.Set();
                            }
                            break;
                        default:
                            break;
                    }
                }
            }
        }

        private void ProcessRecord(DTLSRecord record)
        {
            try
            {
#if DEBUG
            Console.WriteLine(record.RecordType.ToString());
#endif
                switch (record.RecordType)
                {
                    case TRecordType.ChangeCipherSpec:
                        if (_ServerEpoch.HasValue)
                        {
                            _ServerEpoch++;
                            _ServerSequenceNumber = 0;
                            _EncyptedServerEpoch = _ServerEpoch;
                        }
                        break;
                    case TRecordType.Alert:
                        AlertRecord alertRecord;
                        try
                        {
                            if ((_Cipher == null) || (!_EncyptedServerEpoch.HasValue))
                            {
                                alertRecord = AlertRecord.Deserialise(record.Fragment);
                            }
                            else
                            {
                                long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                                byte[] data = _Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.Alert, record.Fragment, 0, record.Fragment.Length);
                                alertRecord = AlertRecord.Deserialise(data);
                            }
                        }
                        catch
                        {
                            alertRecord = new AlertRecord();
                            alertRecord.AlertLevel = TAlertLevel.Fatal;
                        }
                        if (alertRecord.AlertLevel == TAlertLevel.Fatal)
                        {
                            _Connected.Set();
                            //Terminate
                        }
                        else if ((alertRecord.AlertLevel == TAlertLevel.Warning) || (alertRecord.AlertDescription == TAlertDescription.CloseNotify))
                        {
                            if (alertRecord.AlertDescription == TAlertDescription.CloseNotify)
                            {
                                SendAlert(TAlertLevel.Warning, TAlertDescription.CloseNotify);
                                _Connected.Set();
                            }
                            //_Sessions.Remove(session, address);
                        }
                        break;
                    case TRecordType.Handshake:
                        ProcessHandshake(record);
                        _ServerSequenceNumber = record.SequenceNumber + 1;
                        break;
                    case TRecordType.ApplicationData:
                        if (_Cipher != null)
                        {
                            long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                            byte[] data = _Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.ApplicationData, record.Fragment, 0, record.Fragment.Length);
                            if (DataReceived != null)
                            {
                                DataReceived(record.RemoteEndPoint, data);
                            }
                        }
                        _ServerSequenceNumber = record.SequenceNumber + 1;
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
            }
        }

        private void ProcessRecords()
        {
            while (!_Terminate)
            {
                _TriggerProcessRecords.Reset();
                DTLSRecord record = _Records.PeekRecord();
                while (record != null)
                {
                    if (_ServerEpoch.HasValue)
                    {
                        if ((_ServerSequenceNumber == record.SequenceNumber) && (_ServerEpoch == record.Epoch))
                        {
                            _Records.RemoveRecord();
                            ProcessRecord(record);
                            record = _Records.PeekRecord();
                        }
                        else
                        {
                            record = null;
                        }
                    }
                    else
                    {
                        _Records.RemoveRecord();
                        ProcessRecord(record);
                        record = _Records.PeekRecord();
                    }
                }
                if (!_Terminate)
                    _TriggerProcessRecords.WaitOne();
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
                        _Records.Add(record);
                        _TriggerProcessRecords.Set();
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
                // do not throw SocketError.ConnectionReset by ignoring ICMP Port Unreachable
                const Int32 SIO_UDP_CONNRESET = -1744830452;
                result.IOControl(SIO_UDP_CONNRESET, new Byte[] { 0 }, null);
            }
            return result;
        }


        public void Send(byte[] data)
        {
            try
            {
                DTLSRecord record = new DTLSRecord();
                record.RecordType = TRecordType.ApplicationData;
                record.Epoch = _Epoch;
                record.SequenceNumber = NextSequenceNumber();
                if (_Version != null)
                    record.Version = _Version;
                long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                record.Fragment = _Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.ApplicationData, data, 0, data.Length);
                int responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                byte[] response = new byte[responseSize];
                using (MemoryStream stream = new MemoryStream(response))
                {
                    record.Serialise(stream);
                }
                SocketAsyncEventArgs parameters = new SocketAsyncEventArgs()
                {
                    RemoteEndPoint = _ServerEndPoint
                };
                parameters.SetBuffer(response, 0, responseSize);
                if (_Socket != null)
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

        private void SendAlert(TAlertLevel alertLevel, TAlertDescription alertDescription)
        {
            DTLSRecord record = new DTLSRecord();
            record.RecordType = TRecordType.Alert;
            record.Epoch = _Epoch;
            record.SequenceNumber = NextSequenceNumber();
            if (_Version != null)
                record.Version = _Version;
            long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;

            byte[] data = new byte[2];
            data[0] = (byte)alertLevel;
            data[1] = (byte)alertDescription;
            if (_Cipher == null)
                record.Fragment = data;
            else
                record.Fragment = _Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.ApplicationData, data, 0, data.Length);
            int responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
            byte[] response = new byte[responseSize];
            using (MemoryStream stream = new MemoryStream(response))
            {
                record.Serialise(stream);
            }
            SocketAsyncEventArgs parameters = new SocketAsyncEventArgs()
            {
                RemoteEndPoint = _ServerEndPoint
            };
            parameters.SetBuffer(response, 0, responseSize);
            _Socket.SendToAsync(parameters);
        }

        private void SendChangeCipherSpec()
        {
            int size = 1;
            int responseSize = DTLSRecord.RECORD_OVERHEAD + size;
            byte[] response = new byte[responseSize];
            DTLSRecord record = new DTLSRecord();
            record.RecordType = TRecordType.ChangeCipherSpec;
            record.Epoch = _Epoch;
            record.SequenceNumber = NextSequenceNumber();
            record.Fragment = new byte[size];
            record.Fragment[0] = 1;
            if (_Version != null)
                record.Version = _Version;
            using (MemoryStream stream = new MemoryStream(response))
            {
                record.Serialise(stream);
            }
            SocketAsyncEventArgs parameters = new SocketAsyncEventArgs()
            {
                RemoteEndPoint = _ServerEndPoint
            };
            parameters.SetBuffer(response, 0, responseSize);
            _Socket.SendToAsync(parameters);
            ChangeEpoch();
        }

        private void SendHello(byte[] cookie)
        {
            ClientHello clientHello = new ClientHello();
            clientHello.ClientVersion = SupportedVersion;
            clientHello.Random = _HandshakeInfo.ClientRandom;
            clientHello.Cookie = cookie;
            ushort[] cipherSuites = new ushort[_SupportedCipherSuites.Count];
            int index = 0;
            foreach (TCipherSuite item in _SupportedCipherSuites)
            {
                cipherSuites[index] = (ushort)item;
                index++;
            }
            clientHello.CipherSuites = cipherSuites;
            clientHello.CompressionMethods = new byte[1];
            clientHello.CompressionMethods[0] = 0;
            clientHello.Extensions = new Extensions();

            clientHello.Extensions.Add(new Extension() {  ExtensionType = TExtensionType.EncryptThenMAC});
            clientHello.Extensions.Add(new Extension() { ExtensionType = TExtensionType.ExtendedMasterSecret });
            
            EllipticCurvesExtension ellipticCurvesExtension = new EllipticCurvesExtension();
            for (int curve = 0; curve < (int)TEllipticCurve.secp521r1; curve++)
            {
                if (EllipticCurveFactory.SupportedCurve((TEllipticCurve)curve))
                {
                    ellipticCurvesExtension.SupportedCurves.Add((TEllipticCurve)curve);

                }
            }
            clientHello.Extensions.Add(new Extension(ellipticCurvesExtension));
            EllipticCurvePointFormatsExtension cllipticCurvePointFormatsExtension = new EllipticCurvePointFormatsExtension();
            cllipticCurvePointFormatsExtension.SupportedPointFormats.Add(TEllipticCurvePointFormat.Uncompressed);
            clientHello.Extensions.Add(new Extension(cllipticCurvePointFormatsExtension));
            SignatureAlgorithmsExtension signatureAlgorithmsExtension = new SignatureAlgorithmsExtension();
            signatureAlgorithmsExtension.SupportedAlgorithms.Add(new SignatureHashAlgorithm() { Hash= THashAlgorithm.SHA256, Signature = TSignatureAlgorithm.ECDSA });
            clientHello.Extensions.Add(new Extension(signatureAlgorithmsExtension));
            _HandshakeInfo.InitaliseHandshakeHash(false);
            SendHandshakeMessage(clientHello, false);
        }

        private void SendHandshakeMessage(IHandshakeMessage handshakeMessage, bool encrypt)
        {
            int size = handshakeMessage.CalculateSize(_Version);
            int maxPayloadSize = _MaxPacketSize - DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD;
            if (size > maxPayloadSize)
            {

            }
            else
            {

                DTLSRecord record = new DTLSRecord();
                record.RecordType = TRecordType.Handshake;
                record.Epoch = _Epoch;
                record.SequenceNumber = NextSequenceNumber();
                record.Fragment = new byte[HandshakeRecord.RECORD_OVERHEAD + size];
                if (_Version != null)
                    record.Version = _Version;
                HandshakeRecord handshakeRecord = new HandshakeRecord();
                handshakeRecord.MessageType = handshakeMessage.MessageType;
                handshakeRecord.MessageSeq = _MessageSequence;
                _MessageSequence++;
                handshakeRecord.Length = (uint)size;
                handshakeRecord.FragmentLength = (uint)size;
                using (MemoryStream stream = new MemoryStream(record.Fragment))
                {
                    handshakeRecord.Serialise(stream);
                    handshakeMessage.Serialise(stream, _Version);
                }
                if (handshakeMessage.MessageType != THandshakeType.HelloVerifyRequest)
                {
                    _HandshakeInfo.UpdateHandshakeHash(record.Fragment);
                }
                int responseSize = DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD + size;
                if ((_Cipher != null) && encrypt)
                {
                    long sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                    record.Fragment = _Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
                    responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                }
                byte[] response = new byte[responseSize];
                using (MemoryStream stream = new MemoryStream(response))
                {
                    record.Serialise(stream);
                }
                SocketAsyncEventArgs parameters = new SocketAsyncEventArgs()
                {
                    RemoteEndPoint = _ServerEndPoint
                };
                parameters.SetBuffer(response, 0, responseSize);
                _Socket.SendToAsync(parameters);
            }


        }

        public void ConnectToServer(EndPoint serverEndPoint)
        {
            ConnectToServerAsync(serverEndPoint);
            _Connected.WaitOne();
        }

        public void ConnectToServerAsync(EndPoint serverEndPoint)
        {
            _ServerEndPoint = serverEndPoint;
            if (_SupportedCipherSuites.Count == 0)
            {
                _SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8); //Test 1.2
                _SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                _SupportedCipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8); //Test 1.2
                _SupportedCipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                _SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
            }
            _Socket = SetupSocket(_LocalEndPoint.AddressFamily);
            if (_Socket != null)
            {
                _Socket.Bind(_LocalEndPoint);
                _ProcessRecordsThread = new Thread(new ThreadStart(ProcessRecords));
                if (_ProcessRecordsThread.Name == null)
                    _ProcessRecordsThread.Name = "ProcessRecordsThread";
                _ProcessRecordsThread.IsBackground = true;
                _ProcessRecordsThread.Start();
                StartReceive(_Socket);
                SendHello(null);
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

        public void SetVersion(Version version) 
        {
            _Version = version;
        }

        public void Stop()
        {
            if (_Socket != null)
            {
                _Terminate = true;
                _TriggerProcessRecords.Set();
                SendAlert(TAlertLevel.Fatal, TAlertDescription.CloseNotify);
                Thread.Sleep(100);
                _Socket.Dispose();
                _Socket = null;
            }
        }

    }
}
