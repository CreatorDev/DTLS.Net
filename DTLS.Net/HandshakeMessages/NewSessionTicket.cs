using System;
using System.IO;

namespace DTLS
{
    //struct {
    //      opaque key_name[16];
    //      opaque iv[16];
    //      opaque encrypted_state<0..2^16-1>;
    //      opaque mac[32];
    //  } ticket;

    internal class NewSessionTicket : IHandshakeMessage
    {
        public THandshakeType MessageType => THandshakeType.NewSessionTicket;

        public uint LifetimeHint { get; set; }
        public ushort Length { get; set; }
        public byte[] Ticket { get; set; }

        public int CalculateSize(Version version)
        {
            var result = 6;

            if(this.Ticket != null)
            {
                result += this.Ticket.Length;
            }

            return result;
        }

        public static NewSessionTicket Deserialise(Stream stream)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            var result = new NewSessionTicket
            {
                LifetimeHint = (uint)stream.ReadByte(),
                Length = NetworkByteOrderConverter.ToUInt16(stream)
            };

            stream.Read(result.Ticket, 0, result.Length);
            return result;
        }

        public void Serialise(Stream stream, Version version)
        {
            if (stream == null)
            {
                throw new ArgumentNullException(nameof(stream));
            }

            NetworkByteOrderConverter.WriteUInt32(stream, this.LifetimeHint);

            if (this.Ticket == null)
            {
                NetworkByteOrderConverter.WriteUInt16(stream, 0);
            }
            else
            {
                NetworkByteOrderConverter.WriteUInt16(stream, this.Length);
                stream.Write(this.Ticket, 0, this.Ticket.Length);
            }
        }
    }
}
