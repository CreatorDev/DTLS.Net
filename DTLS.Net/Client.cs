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
#if !NET452 && !NET47
using System.Runtime.InteropServices;
#endif
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;

namespace DTLS
{
    public class Client : IDisposable
#if NET6_0_OR_GREATER
        , IAsyncDisposable
#endif
    {
        private static readonly Version _SupportedVersion = DTLSRecord.Version1_2;
        private readonly HandshakeInfo _HandshakeInfo = new();
        private readonly DTLSRecords _Records = new();
        private readonly List<byte[]> _FragmentedRecordList = [];
        private readonly CancellationTokenSource _Cts = new();

        //The maximum safe UDP payload is 508 bytes. Except on an IPv6-only route, where the maximum payload is 1,212 bytes.
        //https://stackoverflow.com/questions/1098897/what-is-the-largest-safe-udp-packet-size-on-the-internet#:~:text=The%20maximum%20safe%20UDP%20payload%20is%20508%20bytes.&text=Except%20on%20an%20IPv6%2Donly,bytes%20may%20be%20preferred%20instead.
        private static int _MaxPacketSize = 1212;
        [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0052:Remove unread private members", Justification = "Need to hold onto the task so it's not GC'd")]
        private Task _ReceiveTask;
        [System.Diagnostics.CodeAnalysis.SuppressMessage("CodeQuality", "IDE0052:Remove unread private members", Justification = "Need to hold onto the task so it's not GC'd")]
        private Task _ProcessRecordTask;
        private Action<EndPoint, byte[]> _DataReceivedFunction;
        private Socket _Socket;
        private bool _Terminate;
        private EndPoint _ServerEndPoint;
        private ushort? _ServerEpoch;
        private long _ServerSequenceNumber;
        private ushort? _EncyptedServerEpoch;
        private ushort _Epoch;
        private ushort _MessageSequence;
        private TlsCipher _Cipher;
        private Version _Version = _SupportedVersion;
        private bool _SendCertificate;
        private IHandshakeMessage _ClientKeyExchange;
        private Certificate _Certificate;
        private AsymmetricKeyParameter _PrivateKey;
        private PSKIdentity _PSKIdentity;

        private byte[] _ReceivedData = [];
        private byte[] _RecvDataBuffer = [];
        private bool _IsFragment = false;
        private bool _ConnectionComplete = false;
        private bool _Disposed = false;
        private long _SequenceNumber = -1; //really only 48 bit

        public EndPoint LocalEndPoint { get; }

        public PSKIdentities PSKIdentities { get; }

        public List<TCipherSuite> SupportedCipherSuites { get; }
        public byte[] ServerCertificate { get; set; }

        private CngKey _PrivateKeyRsa;
        public CngKey PublicKey { get; set; }

        public Client(EndPoint localEndPoint)
            : this(localEndPoint, [])
        {
            SupportedCipherSuites = [];
            if (localEndPoint.AddressFamily != AddressFamily.InterNetworkV6)
            {
                _MaxPacketSize = 508;
            }
        }

        public Client(EndPoint localEndPoint, List<TCipherSuite> supportedCipherSuites)
        {
            LocalEndPoint = localEndPoint ?? throw new ArgumentNullException(nameof(localEndPoint));
            SupportedCipherSuites = supportedCipherSuites ?? throw new ArgumentNullException(nameof(supportedCipherSuites));
            PSKIdentities = new PSKIdentities();
            _HandshakeInfo.ClientRandom = new RandomData();
            _HandshakeInfo.ClientRandom.Generate();
        }

        private void ChangeEpoch()
        {
            ++_Epoch;
            _SequenceNumber = -1;
        }

        private long NextSequenceNumber() => ++_SequenceNumber;

        private async Task ProcessHandshakeAsync(DTLSRecord record)
        {
            if (record == null)
            {
                throw new ArgumentNullException(nameof(record));
            }

            var data = record.Fragment;
            if (_EncyptedServerEpoch == record.Epoch)
            {
                var count = 0;
                while ((_Cipher == null) && (count < 500))
                {
                    await Task.Delay(10).ConfigureAwait(false);
                    count++;
                }

                if (_Cipher == null)
                {
                    throw new Exception("Need Cipher for Encrypted Session");
                }

                var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                data = _Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
            }

            using (var tempStream = new MemoryStream(data))
            {
                var handshakeRec = HandshakeRecord.Deserialise(tempStream);
                if (handshakeRec.Length > (handshakeRec.FragmentLength + handshakeRec.FragmentOffset))
                {
                    _IsFragment = true;
                    _FragmentedRecordList.Add(data);
                    return;
                }
                else if (_IsFragment)
                {
                    _FragmentedRecordList.Add(data);
                    data = [];
                    foreach (var rec in _FragmentedRecordList)
                    {
                        data = [.. data, .. rec.Skip(HandshakeRecord.RECORD_OVERHEAD)];
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

                    data = [.. tempHandshakeBytes, .. data];
                }
            }

            using (var stream = new MemoryStream(data))
            {
                var handshakeRecord = HandshakeRecord.Deserialise(stream);
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
                            _HandshakeInfo.UpdateHandshakeHash(data);
                            _ServerEpoch = record.Epoch;
                            _HandshakeInfo.CipherSuite = (TCipherSuite)serverHello.CipherSuite;
                            _HandshakeInfo.ServerRandom = serverHello.Random;
                            _Version = serverHello.ServerVersion <= _Version ? serverHello.ServerVersion : _SupportedVersion;
                            break;
                        }
                    case THandshakeType.HelloVerifyRequest:
                        {
                            var helloVerifyRequest = HelloVerifyRequest.Deserialise(stream);
                            _Version = helloVerifyRequest.ServerVersion;
                            await SendHelloAsync(helloVerifyRequest.Cookie).ConfigureAwait(false);
                            break;
                        }
                    case THandshakeType.Certificate:
                        {
                            var cert = Certificate.Deserialise(stream, TCertificateType.X509);
                            _HandshakeInfo.UpdateHandshakeHash(data);
                            ServerCertificate = cert.Cert;
                            break;
                        }
                    case THandshakeType.ServerKeyExchange:
                        {
                            _HandshakeInfo.UpdateHandshakeHash(data);
                            var keyExchangeAlgorithm = CipherSuites.GetKeyExchangeAlgorithm(_HandshakeInfo.CipherSuite);
                            byte[] preMasterSecret = null;
                            IKeyExchange keyExchange = null;
                            if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_ECDSA)
                            {
                                var serverKeyExchange = ECDHEServerKeyExchange.Deserialise(stream, _Version);
                                var keyExchangeECDHE = new ECDHEKeyExchange
                                {
                                    CipherSuite = _HandshakeInfo.CipherSuite,
                                    Curve = serverKeyExchange.EllipticCurve,
                                    KeyExchangeAlgorithm = keyExchangeAlgorithm,
                                    ClientRandom = _HandshakeInfo.ClientRandom,
                                    ServerRandom = _HandshakeInfo.ServerRandom
                                };
                                keyExchangeECDHE.GenerateEphemeralKey();
                                var clientKeyExchange = new ECDHEClientKeyExchange(keyExchangeECDHE.PublicKey);
                                _ClientKeyExchange = clientKeyExchange;
                                preMasterSecret = keyExchangeECDHE.GetPreMasterSecret(serverKeyExchange.PublicKeyBytes);
                                keyExchange = keyExchangeECDHE;
                            }
                            else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.ECDHE_PSK)
                            {
                                var serverKeyExchange = ECDHEPSKServerKeyExchange.Deserialise(stream);
                                var keyExchangeECDHE = new ECDHEKeyExchange
                                {
                                    CipherSuite = _HandshakeInfo.CipherSuite,
                                    Curve = serverKeyExchange.EllipticCurve,
                                    KeyExchangeAlgorithm = keyExchangeAlgorithm,
                                    ClientRandom = _HandshakeInfo.ClientRandom,
                                    ServerRandom = _HandshakeInfo.ServerRandom
                                };
                                keyExchangeECDHE.GenerateEphemeralKey();
                                var clientKeyExchange = new ECDHEPSKClientKeyExchange(keyExchangeECDHE.PublicKey);
                                if (serverKeyExchange.PSKIdentityHint != null)
                                {
                                    var key = PSKIdentities.GetKey(serverKeyExchange.PSKIdentityHint);
                                    if (key != null)
                                    {
                                        _PSKIdentity = new PSKIdentity() { Identity = serverKeyExchange.PSKIdentityHint, Key = key };
                                    }
                                }
                                _PSKIdentity ??= PSKIdentities.GetRandom();

                                clientKeyExchange.PSKIdentity = _PSKIdentity.Identity;
                                _ClientKeyExchange = clientKeyExchange;
                                var otherSecret = keyExchangeECDHE.GetPreMasterSecret(serverKeyExchange.PublicKeyBytes);
                                preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, _PSKIdentity.Key);
                                keyExchange = keyExchangeECDHE;
                            }
                            else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                            {
                                var serverKeyExchange = PSKServerKeyExchange.Deserialise(stream);
                                var clientKeyExchange = new PSKClientKeyExchange();
                                if (serverKeyExchange.PSKIdentityHint != null)
                                {
                                    var key = PSKIdentities.GetKey(serverKeyExchange.PSKIdentityHint);
                                    if (key != null)
                                    {
                                        _PSKIdentity = new PSKIdentity() { Identity = serverKeyExchange.PSKIdentityHint, Key = key };
                                    }
                                }
                                _PSKIdentity ??= PSKIdentities.GetRandom();

                                var otherSecret = new byte[_PSKIdentity.Key.Length];
                                clientKeyExchange.PSKIdentity = _PSKIdentity.Identity;
                                _ClientKeyExchange = clientKeyExchange;
                                preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, _PSKIdentity.Key);
                            }
                            _Cipher = TLSUtils.AssignCipher(preMasterSecret, true, _Version, _HandshakeInfo);
                            break;
                        }
                    case THandshakeType.CertificateRequest:
                        {
                            _HandshakeInfo.UpdateHandshakeHash(data);
                            _SendCertificate = true;
                            break;
                        }
                    case THandshakeType.ServerHelloDone:
                        {
                            _HandshakeInfo.UpdateHandshakeHash(data);
                            var keyExchangeAlgorithm = CipherSuites.GetKeyExchangeAlgorithm(_HandshakeInfo.CipherSuite);
                            if (_Cipher == null)
                            {
                                if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.PSK)
                                {
                                    var clientKeyExchange = new PSKClientKeyExchange();
                                    _PSKIdentity = PSKIdentities.GetRandom();
                                    var otherSecret = new byte[_PSKIdentity.Key.Length];
                                    clientKeyExchange.PSKIdentity = _PSKIdentity.Identity;
                                    _ClientKeyExchange = clientKeyExchange;
                                    var preMasterSecret = TLSUtils.GetPSKPreMasterSecret(otherSecret, _PSKIdentity.Key);
                                    _Cipher = TLSUtils.AssignCipher(preMasterSecret, true, _Version, _HandshakeInfo);
                                }
                                else if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.RSA)
                                {
                                    var clientKeyExchange = new RSAClientKeyExchange();
                                    _ClientKeyExchange = clientKeyExchange;
                                    var PreMasterSecret = TLSUtils.GetRsaPreMasterSecret(_Version);
                                    clientKeyExchange.PremasterSecret = TLSUtils.GetEncryptedRsaPreMasterSecret(ServerCertificate, PreMasterSecret);
                                    _Cipher = TLSUtils.AssignCipher(PreMasterSecret, true, _Version, _HandshakeInfo);
                                }
                                else
                                {
                                    throw new NotImplementedException($"Key Exchange Algorithm {keyExchangeAlgorithm} Not Implemented");
                                }
                            }

                            if (_SendCertificate)
                            {
                                await SendHandshakeMessageAsync(_Certificate, false).ConfigureAwait(false);
                            }

                            await SendHandshakeMessageAsync(_ClientKeyExchange, false).ConfigureAwait(false);

                            if (_SendCertificate)
                            {
                                var signatureHashAlgorithm = new SignatureHashAlgorithm() { Signature = TSignatureAlgorithm.ECDSA, Hash = THashAlgorithm.SHA256 };
                                if (keyExchangeAlgorithm == TKeyExchangeAlgorithm.RSA)
                                {
                                    signatureHashAlgorithm = new SignatureHashAlgorithm() { Signature = TSignatureAlgorithm.RSA, Hash = THashAlgorithm.SHA1 };
                                }

                                var certVerify = new CertificateVerify
                                {
                                    SignatureHashAlgorithm = signatureHashAlgorithm,
                                    Signature = TLSUtils.Sign(_PrivateKey, _PrivateKeyRsa, true, _Version, _HandshakeInfo, signatureHashAlgorithm, _HandshakeInfo.GetHash(_Version))
                                };

                                await SendHandshakeMessageAsync(certVerify, false).ConfigureAwait(false);
                            }

                            await SendChangeCipherSpecAsync().ConfigureAwait(false);
                            var handshakeHash = _HandshakeInfo.GetHash(_Version);
                            var finished = new Finished
                            {
                                VerifyData = TLSUtils.GetVerifyData(_Version, _HandshakeInfo, true, true, handshakeHash)
                            };

                            await SendHandshakeMessageAsync(finished, true).ConfigureAwait(false);
                            break;
                        }
                    case THandshakeType.NewSessionTicket:
                        {
                            _HandshakeInfo.UpdateHandshakeHash(data);
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
                            var handshakeHash = _HandshakeInfo.GetHash(_Version);
                            var calculatedVerifyData = TLSUtils.GetVerifyData(_Version, _HandshakeInfo, true, false, handshakeHash);
                            if (serverFinished.VerifyData.SequenceEqual(calculatedVerifyData))
                            {
                                _ConnectionComplete = true;
                            }
                            break;
                        }
                    default:
                        {
                            break;
                        }
                }
            }

            _IsFragment = false;
            _FragmentedRecordList.RemoveAll(x => true);
        }

        private async Task ProcessRecordAsync(DTLSRecord record)
        {
            try
            {
                if (record == null)
                {
                    throw new ArgumentNullException(nameof(record));
                }

                switch (record.RecordType)
                {
                    case TRecordType.ChangeCipherSpec:
                        {
                            _ReceivedData = [];
                            if (_ServerEpoch.HasValue)
                            {
                                _ServerEpoch++;
                                _ServerSequenceNumber = 0;
                                _EncyptedServerEpoch = _ServerEpoch;
                            }
                            break;
                        }
                    case TRecordType.Alert:
                        {
                            _ReceivedData = [];
                            AlertRecord alertRecord;
                            try
                            {
                                if ((_Cipher == null) || (!_EncyptedServerEpoch.HasValue))
                                {
                                    alertRecord = AlertRecord.Deserialise(record.Fragment);
                                }
                                else
                                {
                                    var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                                    var data = _Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.Alert, record.Fragment, 0, record.Fragment.Length);
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
                                _ConnectionComplete = true;
                            }
                            else if ((alertRecord.AlertLevel == TAlertLevel.Warning) || (alertRecord.AlertDescription == TAlertDescription.CloseNotify))
                            {
                                if (alertRecord.AlertDescription == TAlertDescription.CloseNotify)
                                {
                                    await SendAlertAsync(TAlertLevel.Warning, TAlertDescription.CloseNotify).ConfigureAwait(false);
                                    _ConnectionComplete = true;
                                }
                            }
                            break;
                        }
                    case TRecordType.Handshake:
                        {
                            _ReceivedData = [];
                            await ProcessHandshakeAsync(record).ConfigureAwait(false);
                            _ServerSequenceNumber = record.SequenceNumber + 1;
                            break;
                        }
                    case TRecordType.ApplicationData:
                        {
                            if (_Cipher != null)
                            {
                                var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                                var data = _Cipher.DecodeCiphertext(sequenceNumber, (byte)TRecordType.ApplicationData, record.Fragment, 0, record.Fragment.Length);
                                _DataReceivedFunction?.Invoke(record.RemoteEndPoint, data);
                                _ReceivedData = data;
                            }
                            _ServerSequenceNumber = record.SequenceNumber + 1;
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

        private async Task ProcessRecordsAsync()
        {
            while (!_Terminate)
            {
                var record = _Records.PeekRecord();
                while (record != null)
                {
                    if (_ServerEpoch.HasValue && (_ServerSequenceNumber != record.SequenceNumber || _ServerEpoch != record.Epoch))
                    {
                        record = null;
                    }
                    else
                    {
                        _Records.RemoveRecord();
                        await ProcessRecordAsync(record).ConfigureAwait(false);
                        record = _Records.PeekRecord();
                    }
                }

                await Task.Delay(100).ConfigureAwait(false);
            }
        }

        private void ReceiveCallback(byte[] recvData, EndPoint ip)
        {
            if (recvData == null)
            {
                throw new ArgumentNullException(nameof(recvData));
            }

            if (ip == null)
            {
                throw new ArgumentNullException(nameof(ip));
            }

            if (!recvData.Any())
            {
                //nothing received? return?
                return;
            }

            if (recvData.Length < 13)
            {
                _RecvDataBuffer = [.. _RecvDataBuffer, .. recvData];
                return;
            }

            var length = BitConverter.ToUInt16(recvData.Skip(11).Take(2).Reverse().ToArray(), 0);
            if (recvData.Length < length)
            {
                _RecvDataBuffer = [.. _RecvDataBuffer, .. recvData];
                return;
            }

            var fullData = _RecvDataBuffer.Concat(recvData).ToArray();
            _RecvDataBuffer = [];

            using (var stream = new MemoryStream(fullData))
            {
                while (stream.Position < stream.Length)
                {
                    var record = DTLSRecord.Deserialise(stream);
                    record.RemoteEndPoint = ip;
                    _Records.Add(record);
                }
            }
        }

        private async Task<Socket> SetupSocketAsync()
        {
            var addressFamily = LocalEndPoint.AddressFamily;
            var soc = new Socket(addressFamily, SocketType.Dgram, ProtocolType.Udp);
            if (addressFamily == AddressFamily.InterNetworkV6)
            {
                soc.SetSocketOption(SocketOptionLevel.IPv6, SocketOptionName.IPv6Only, true);
            }
#if NET452 || NET47
            if (Environment.OSVersion.Platform != PlatformID.Unix)
#else
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
#endif
            {
                // do not throw SocketError.ConnectionReset by ignoring ICMP Port Unreachable
                const int SIO_UDP_CONNRESET = -1744830452;
                soc.IOControl(SIO_UDP_CONNRESET, [0], null);
            }

            await soc.ConnectAsync(_ServerEndPoint).ConfigureAwait(false);
            return soc;
        }

        public async Task SendAsync(byte[] data) =>
            await SendAsync(data, TimeSpan.FromSeconds(1)).ConfigureAwait(false);

        public async Task SendAsync(byte[] data, TimeSpan timeout)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            if (_Socket == null)
            {
                throw new Exception("Socket Cannot be Null");
            }

            if (_Cipher == null)
            {
                throw new Exception("Cipher Cannot be Null");
            }

            var record = new DTLSRecord
            {
                RecordType = TRecordType.ApplicationData,
                Epoch = _Epoch,
                SequenceNumber = NextSequenceNumber(),
                Version = _Version
            };

            var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
            record.Fragment = _Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.ApplicationData, data, 0, data.Length);

            var recordSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
            var recordBytes = new byte[recordSize];
            using (var stream = new MemoryStream(recordBytes))
            {
                record.Serialise(stream);
            }

#if NET6_0_OR_GREATER
            var ct = new CancellationTokenSource(timeout).Token;
            await _Socket.SendAsync(new ReadOnlyMemory<byte>(recordBytes), SocketFlags.None, ct).ConfigureAwait(false);
#else
            await _Socket.SendAsync(recordBytes, timeout).ConfigureAwait(false);
#endif
        }

        public async Task<byte[]> SendAndGetResponseAsync(byte[] data, TimeSpan timeout)
        {
            await SendAsync(data, timeout).ConfigureAwait(false);
            return await ReceiveDataAsync(timeout).ConfigureAwait(false);
        }

        public async Task<byte[]> SendAndGetResonseAsync(byte[] data) =>
            await SendAndGetResponseAsync(data, TimeSpan.FromSeconds(5)).ConfigureAwait(false);

        public async Task<byte[]> ReceiveDataAsync() =>
            await ReceiveDataAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);

        public async Task<byte[]> ReceiveDataAsync(TimeSpan timeout)
        {
            var startTime = DateTime.Now;
            while ((_ReceivedData == null || !_ReceivedData.Any()))
            {
                if ((DateTime.Now - startTime) >= timeout)
                {
                    throw new TimeoutException();
                }

                await Task.Delay(100).ConfigureAwait(false);
            }

            return _ReceivedData;
        }

        private async Task SendAlertAsync(TAlertLevel alertLevel, TAlertDescription alertDescription) =>
           await SendAlertAsync(alertLevel, alertDescription, TimeSpan.FromSeconds(1)).ConfigureAwait(false);

        private async Task SendAlertAsync(TAlertLevel alertLevel, TAlertDescription alertDescription, TimeSpan timeout)
        {
            if (_Socket == null)
            {
                throw new Exception("Soket Cannot be Null");
            }

            var record = new DTLSRecord
            {
                RecordType = TRecordType.Alert,
                Epoch = _Epoch,
                SequenceNumber = NextSequenceNumber(),
                Version = _Version
            };

            var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;

            var data = new byte[2];
            data[0] = (byte)alertLevel;
            data[1] = (byte)alertDescription;
            record.Fragment = _Cipher == null ? data : _Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.ApplicationData, data, 0, data.Length);
            var recordSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
            var recordBytes = new byte[recordSize];
            using (var stream = new MemoryStream(recordBytes))
            {
                record.Serialise(stream);
            }

            await _Socket.SendAsync(recordBytes, timeout).ConfigureAwait(false);
        }

        private async Task SendChangeCipherSpecAsync() =>
            await SendChangeCipherSpecAsync(TimeSpan.FromSeconds(1)).ConfigureAwait(false);

        private async Task SendChangeCipherSpecAsync(TimeSpan timeout)
        {
            if (_Socket == null)
            {
                throw new Exception("Socket Cannot be Null");
            }

            var bytes = GetChangeCipherSpec();
            await _Socket.SendAsync(bytes, timeout).ConfigureAwait(false);
            ChangeEpoch();
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
                SequenceNumber = NextSequenceNumber(),
                Fragment = new byte[size],
                Version = _Version
            };

            record.Fragment[0] = 1;
            using (var stream = new MemoryStream(response))
            {
                record.Serialise(stream);
            }
            return response;
        }

        private List<byte[]> GetBytes(IHandshakeMessage handshakeMessage, bool encrypt)
        {
            if (handshakeMessage == null)
            {
                throw new ArgumentNullException(nameof(handshakeMessage));
            }

            var size = handshakeMessage.CalculateSize(_Version);
            var maxPayloadSize = _MaxPacketSize - DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD;

            if (size > maxPayloadSize)
            {
                var wholeMessage = new List<byte[]>();

                var record = new DTLSRecord
                {
                    RecordType = TRecordType.Handshake,
                    Epoch = _Epoch,
                    Version = _Version
                };

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
                        handshakeMessage.Serialise(stream, _Version);
                    }

                    _HandshakeInfo.UpdateHandshakeHash(record.Fragment);
                }

                var dataMessage = new byte[size];
                using (var stream = new MemoryStream(dataMessage))
                {
                    handshakeMessage.Serialise(stream, _Version);
                }

                var dataMessageFragments = dataMessage.ChunkBySize(maxPayloadSize);
                handshakeRecord.FragmentOffset = 0U;
                dataMessageFragments.ForEach(x =>
                {
                    handshakeRecord.Length = (uint)size;
                    handshakeRecord.FragmentLength = (uint)x.Count();
                    record.SequenceNumber = NextSequenceNumber();

                    var baseMessage = new byte[HandshakeRecord.RECORD_OVERHEAD];
                    using (var stream = new MemoryStream(baseMessage))
                    {
                        handshakeRecord.Serialise(stream);
                    }

                    record.Fragment = [.. baseMessage, .. x];

                    var responseSize = DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD + x.Count();
                    if ((_Cipher != null) && encrypt)
                    {
                        var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                        record.Fragment = _Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
                        responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                    }
                    var response = new byte[responseSize];
                    using (var stream = new MemoryStream(response))
                    {
                        record.Serialise(stream);
                    }

                    wholeMessage.Add(response);
                    handshakeRecord.FragmentOffset += (uint)x.Count();
                });

                _MessageSequence++;
                return wholeMessage;
            }
            else
            {
                var record = new DTLSRecord
                {
                    RecordType = TRecordType.Handshake,
                    Epoch = _Epoch,
                    SequenceNumber = NextSequenceNumber(),
                    Fragment = new byte[HandshakeRecord.RECORD_OVERHEAD + size],
                    Version = _Version
                };

                var handshakeRecord = new HandshakeRecord
                {
                    MessageType = handshakeMessage.MessageType,
                    MessageSeq = _MessageSequence
                };
                _MessageSequence++;
                handshakeRecord.Length = (uint)size;
                handshakeRecord.FragmentLength = (uint)size;
                using (var stream = new MemoryStream(record.Fragment))
                {
                    handshakeRecord.Serialise(stream);
                    handshakeMessage.Serialise(stream, _Version);
                }

                if (!(handshakeMessage.MessageType == THandshakeType.HelloVerifyRequest
                   || (handshakeMessage.MessageType == THandshakeType.ClientHello && (handshakeMessage as ClientHello).Cookie == null)))
                {
                    _HandshakeInfo.UpdateHandshakeHash(record.Fragment);
                }

                var responseSize = DTLSRecord.RECORD_OVERHEAD + HandshakeRecord.RECORD_OVERHEAD + size;
                if ((_Cipher != null) && encrypt)
                {
                    var sequenceNumber = ((long)record.Epoch << 48) + record.SequenceNumber;
                    record.Fragment = _Cipher.EncodePlaintext(sequenceNumber, (byte)TRecordType.Handshake, record.Fragment, 0, record.Fragment.Length);
                    responseSize = DTLSRecord.RECORD_OVERHEAD + record.Fragment.Length;
                }

                var response = new byte[responseSize];
                using (var stream = new MemoryStream(response))
                {
                    record.Serialise(stream);
                }

                return [response];
            }
        }

        private async Task SendHelloAsync(byte[] cookie)
        {
            var clientHello = new ClientHello
            {
                ClientVersion = _Version,
                Random = _HandshakeInfo.ClientRandom,
                Cookie = cookie
            };

            var cipherSuites = new ushort[SupportedCipherSuites.Count];
            var index = 0;
            foreach (var item in SupportedCipherSuites)
            {
                cipherSuites[index] = (ushort)item;
                index++;
            }
            clientHello.CipherSuites = cipherSuites;
            clientHello.CompressionMethods = new byte[1];
            clientHello.CompressionMethods[0] = 0;

            clientHello.Extensions =
                [
                    new Extension() { ExtensionType = TExtensionType.SessionTicketTLS },
                    new Extension() { ExtensionType = TExtensionType.EncryptThenMAC },
                    new Extension() { ExtensionType = TExtensionType.ExtendedMasterSecret },
                ];

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
            await SendHandshakeMessageAsync(clientHello, false, TimeSpan.FromSeconds(1)).ConfigureAwait(false);
        }

        private async Task SendHandshakeMessageAsync(IHandshakeMessage handshakeMessage, bool encrypt) =>
            await SendHandshakeMessageAsync(handshakeMessage, encrypt, TimeSpan.FromSeconds(1)).ConfigureAwait(false);

        private async Task SendHandshakeMessageAsync(IHandshakeMessage handshakeMessage, bool encrypt, TimeSpan timeout)
        {
            if (handshakeMessage == null)
            {
                throw new ArgumentNullException(nameof(handshakeMessage));
            }

            if (_Socket == null)
            {
                throw new Exception("Socket Cannot be Null");
            }

            var byteArrayList = GetBytes(handshakeMessage, encrypt);
            foreach (var byteArray in byteArrayList)
            {
                Console.WriteLine($"Sending {handshakeMessage.MessageType} {byteArray.Length}");
                await _Socket.SendAsync(byteArray, timeout).ConfigureAwait(false);
            }
        }

        public async Task ConnectToServerAsync(EndPoint serverEndPoint)
        {
            if (serverEndPoint == null)
            {
                throw new ArgumentNullException(nameof(serverEndPoint));
            }

            await ConnectToServerAsync(serverEndPoint, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(5)).ConfigureAwait(false);
        }

        public async Task ConnectToServerAsync(EndPoint serverEndPoint, TimeSpan receiveTimeout, TimeSpan connectionTimeout)
        {
            _ServerEndPoint = serverEndPoint ?? throw new ArgumentNullException(nameof(serverEndPoint));
            if (SupportedCipherSuites.Count == 0)
            {
                SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8); //Test 1.2
                SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                SupportedCipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CCM_8); //Test 1.2
                SupportedCipherSuites.Add(TCipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                SupportedCipherSuites.Add(TCipherSuite.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256); //Tested 1.0 1.2
                SupportedCipherSuites.Add(TCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA);
            }

            _Socket = await SetupSocketAsync().ConfigureAwait(false);
            _ProcessRecordTask = Task.Run(() => ProcessRecordsAsync().ConfigureAwait(false), _Cts.Token); //fire and forget
            _ReceiveTask = Task.Run(() => StartReceiveAsync(_Socket, receiveTimeout).ConfigureAwait(false), _Cts.Token); // fire and forget
            await SendHelloAsync(null).ConfigureAwait(false);

            var startTime = DateTime.Now;
            while (!_ConnectionComplete)
            {
                if ((DateTime.Now - startTime) >= connectionTimeout)
                {
                    throw new TimeoutException("Could Not Connect To Server");
                }

                await Task.Delay(100).ConfigureAwait(false);
            }
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Interoperability", "CA1416:Validate platform compatibility", Justification = "Other methods are available but RSA is just for windows")]
        public void LoadX509Certificate(X509Chain chain)
        {
            if (chain == null)
            {
                throw new ArgumentNullException(nameof(chain));
            }

            var mainCert = chain.ChainElements[0].Certificate;

#pragma warning disable SYSLIB0028 // Type or member is obsolete
            _PrivateKeyRsa = ((RSACng)mainCert.PrivateKey).Key;
#pragma warning restore SYSLIB0028 // Type or member is obsolete
#pragma warning disable SYSLIB0027 // Type or member is obsolete
            PublicKey = ((RSACng)mainCert.PublicKey.Key).Key;
#pragma warning restore SYSLIB0027 // Type or member is obsolete

            var certChain = new List<byte[]>();
            foreach (var element in chain.ChainElements)
            {
                certChain.Add(element.Certificate.GetRawCertData());
            }

            _Certificate = new Certificate
            {
                CertChain = certChain,
                CertificateType = TCertificateType.X509
            };
        }

        public void LoadCertificateFromPem(string filename)
        {
            if (string.IsNullOrWhiteSpace(filename))
            {
                throw new ArgumentNullException(nameof(filename));
            }

            using (var stream = File.OpenRead(filename))
            {
                LoadCertificateFromPem(stream);
            }
        }

        public void LoadCertificateFromPem(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

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
                    _PrivateKey = Certificates.GetPrivateKeyFromPEM(pem);
                }
                pem = reader.ReadPemObject();
            }
            _Certificate = new Certificate
            {
                CertChain = chain,
                CertificateType = TCertificateType.X509
            };
        }

        private async Task StartReceiveAsync(Socket socket, TimeSpan timeout)
        {
            if (socket == null)
            {
                throw new ArgumentNullException(nameof(socket));
            }

            while (!_Terminate)
            {
                var available = socket.Available;
                if (available > 0)
                {
#if NET6_0_OR_GREATER
                    var buffer = new Memory<byte>(new byte[available]);
                    var ct = new CancellationTokenSource(timeout).Token;
                    var recvd = await socket.ReceiveAsync(buffer, SocketFlags.None, ct).ConfigureAwait(false);
                    if (recvd < available)
                    {
                        buffer = buffer[..recvd];
                    }

                    ReceiveCallback(buffer.ToArray(), socket.RemoteEndPoint);
#else
                    var buffer = new byte[available];
                    var recvd = await socket.ReceiveAsync(buffer, timeout).ConfigureAwait(false);
                    if (recvd < available)
                    {
                        buffer = buffer.Take(recvd).ToArray();
                    }

                    ReceiveCallback(buffer, socket.RemoteEndPoint);
#endif
                }
                else
                {
                    await Task.Delay(100).ConfigureAwait(false);
                }
            }
        }

        public void SetDataReceivedFunction(Action<EndPoint, byte[]> function) => _DataReceivedFunction = function;

        public void SetVersion(Version version) => _Version = version ?? throw new ArgumentNullException(nameof(version));

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA1816:Dispose methods should call SuppressFinalize", Justification = "Dipose methods call this one")]
        private async Task Dispose(bool disposing)
        {
            //prevent multiple calls to Dispose
            if (_Disposed)
            {
                return;
            }

            if (disposing)
            {
                _Terminate = true;

                if (_Socket != null)
                {
                    await SendAlertAsync(TAlertLevel.Fatal, TAlertDescription.CloseNotify).ConfigureAwait(false);
                    _Socket.Dispose();
                    _Socket = null;
                }

                _Cts.Cancel();
                _ReceiveTask = null;
                _ProcessRecordTask = null;
            }

            //Tell the GC not to call the finalizer later
            GC.SuppressFinalize(this);
            _Disposed = true;
        }

        [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA1816:Dispose methods should call SuppressFinalize", Justification = "Called in private Dispose")]
        public void Dispose() => Dispose(true).GetAwaiter().GetResult();

#if NET6_0_OR_GREATER
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Usage", "CA1816:Dispose methods should call SuppressFinalize", Justification = "Called in private Dispose")]
        public async ValueTask DisposeAsync() => await Dispose(true);
#endif

        ~Client()
        {
            Dispose(false).GetAwaiter().GetResult();
        }
    }
}
