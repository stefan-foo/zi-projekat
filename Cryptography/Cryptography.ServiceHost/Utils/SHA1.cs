using System.Numerics;
using System.Text;

namespace Cryptography.ServiceHost.Utils
{
    public class SHA1 
    {
        enum Status
        {
            Completed,
            InProgress,
            NotStarted
        }

        private readonly uint[] K = { 
            0x5A827999,                
            0x6ED9EBA1,
            0x8F1BBCDC,
            0xCA62C1D6
        };

        private readonly byte[] buffer = new byte[64];

        Status status = Status.NotStarted;
        private ulong messageLength = 0;
        private string hashResult = "";

        private uint h0, h1, h2, h3, h4;
        private int bi = 0;
        public SHA1()
        {
            Reset();
        }

        public void Reset()
        {
            status = Status.NotStarted;

            h0 = 0x67452301;
            h1 = 0xEFCDAB89;
            h2 = 0x98BADCFE;
            h3 = 0x10325476;
            h4 = 0xC3D2E1F0;

            Array.Clear(buffer);
            messageLength = 0;
            bi = 0;
        }

        public void HashBlock(byte[] data)
        {
            if (status == Status.Completed)
            {
                Reset();
            }

            status = Status.InProgress;

            int i = 0;
            while (i < data.Length)
            {
                var canCopy = Math.Min(buffer.Length - bi, data.Length - i);
                Array.Copy(data, i, buffer, bi, canCopy);

                bi += canCopy;
                i  += canCopy;

                if (bi == buffer.Length)
                {
                    ProcessBlock();
                }
            }

            messageLength += (ulong)i;
        }

        private void ProcessBlock()
        {
            uint[] w = new uint[80];

            for (int i = 0; i < 16; i++)
            {
                w[i] =  (uint)(buffer[i * 4] << 24);
                w[i] |= (uint)(buffer[i * 4 + 1] << 16);
                w[i] |= (uint)(buffer[i * 4 + 2] << 8);
                w[i] |= (uint)(buffer[i * 4 + 3]);
            }

            for (int i = 16; i < 80; i++)
            {
                w[i] = BitOperations.RotateLeft(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
            }

            uint a = h0, b = h1, c = h2, d = h3, e = h4, temp;

            for (int t = 0; t < 20; t++)
            {
                temp = BitOperations.RotateLeft(a, 5) + ((b & c) | ((~b) & d)) + e + w[t] + K[0];
                e = d;
                d = c;
                c = BitOperations.RotateLeft(b, 30);
                b = a;
                a = temp;
            }

            for (int t = 20; t < 40; t++)
            {
                temp = BitOperations.RotateLeft(a, 5) + (b ^ c ^ d) + e + w[t] + K[1];
                e = d;
                d = c;
                c = BitOperations.RotateLeft(b, 30);
                b = a;
                a = temp;
            }

            for (int t = 40; t < 60; t++)
            {
                temp = BitOperations.RotateLeft(a, 5) + ((b & c) | (b & d) | (c & d)) + e + w[t] + K[2];
                e = d;
                d = c;
                c = BitOperations.RotateLeft(b, 30);
                b = a;
                a = temp;
            }

            for (int t = 60; t < 80; t++)
            {
                temp = BitOperations.RotateLeft(a, 5) + (b ^ c ^ d) + e + w[t] + K[3];
                e = d;
                d = c;
                c = BitOperations.RotateLeft(b, 30);
                b = a;
                a = temp;
            }

            h0 += a;
            h1 += b;
            h2 += c;
            h3 += d;
            h4 += e;

            bi = 0;
        }

        private void ProcessFinalBlock()
        {
            if (bi > 55)
            {
                buffer[bi++] = 0x80;
                Array.Clear(buffer, bi, 64 - bi);

                ProcessBlock();

                Array.Clear(buffer, 0, 56);
            }
            else
            {
                buffer[bi++] = 0x80;
                Array.Clear(buffer, bi, 56 - bi);
            }

            messageLength *= 8;

            buffer[56] = (byte)(messageLength >> 56);
            buffer[57] = (byte)(messageLength >> 48);
            buffer[58] = (byte)(messageLength >> 40);
            buffer[59] = (byte)(messageLength >> 32);
            buffer[60] = (byte)(messageLength >> 24);
            buffer[61] = (byte)(messageLength >> 16);
            buffer[62] = (byte)(messageLength >> 8);
            buffer[63] = (byte)(messageLength);

            ProcessBlock();
        }

        public string Result()
        {
            if (status == Status.Completed)
            {
                return hashResult;
            }

            ProcessFinalBlock();

            StringBuilder result = new();

            result.Append("0x");
            result.AppendFormat("{0:x8}", h0);
            result.AppendFormat("{0:x8}", h1);
            result.AppendFormat("{0:x8}", h2);
            result.AppendFormat("{0:x8}", h3);
            result.AppendFormat("{0:x8}", h4);

            hashResult = result.ToString();
            status = Status.Completed;

            return hashResult;
        }

        public bool Verify(string hash)
        {   
            return Result() == hash;
        }
    }
}
