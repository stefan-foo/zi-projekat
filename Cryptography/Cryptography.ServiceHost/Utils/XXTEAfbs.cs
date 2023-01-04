using System.Text;

namespace Cryptography.ServiceHost.Utils
{
    //XXTEA - fixed block size
    //Servis odredjuje velicinu bloka za enkripciju, vrsi se enkripcija tek kada se napuni buffer
    //Ostatak u bufferu na kraju toka podataka se padduje i potom obradjuje kao ceo blok
    public class XXTEAfbs
    {
        private static readonly uint _Delta = 0x9e3779b9;
        private static readonly int _BlockSizeUint32 = 1024;
        private static readonly int _BlockSizeBytes = _BlockSizeUint32 * 4;

        private readonly byte[] buffer = new byte[_BlockSizeBytes];
        private readonly uint[] key;
        private int bi = 0;

        public XXTEAfbs(byte[] key)
        {
            if (key.Length < 16)
            {
                throw new ArgumentException("Kljuc mora biti minimum 16 bajtova");
            }
            this.key = EncryptionHelper.BlockCopy(key, 4);
        }

        public XXTEAfbs(string key) : this(Encoding.UTF8.GetBytes(key))
        {
        }
        
        public bool Empty
        {
            get { return bi == 0; }
        }
        public static int BlockSizeUint32
        {
            get { return _BlockSizeUint32; }
        }

        public IEnumerable<byte[]> Encrypt(byte[] data)
        {
            int i = 0;
            while (i < data.Length)
            {
                var canCopy = Math.Min(buffer.Length - bi, data.Length - i);
                Array.Copy(data, i, buffer, bi, canCopy);

                bi += canCopy;

                if (bi == buffer.Length)
                {
                    yield return EncryptBlock(buffer, BlockSizeUint32);

                    bi = 0;
                }

                i += canCopy;
            }
        }

        public IEnumerable<byte[]> Decrypt(byte[] data)
        {
            int i = 0;
            while (i < data.Length)
            {
                var canCopy = Math.Min(buffer.Length - bi, data.Length - i);
                Array.Copy(data, i, buffer, bi, canCopy);

                bi += canCopy;

                if (bi == buffer.Length)
                {
                    yield return DecryptBlock(buffer, BlockSizeUint32);

                    bi = 0;
                }

                i += canCopy;
            }
        }
        public byte[] EncryptRemaining()
        {
            if (bi == 0)
            {
                return Array.Empty<byte>();
            }

            Array.Clear(buffer, bi, buffer.Length - bi);

            buffer[bi] = 0x80;
            bi = 0;
            return Encrypt(buffer).First();
        }

        public byte[] EncryptBlock(byte[] block, int blockSizeInt32)
        {
            var uint32b = Encrypt(EncryptionHelper.BlockCopy(block, blockSizeInt32), key);
            return EncryptionHelper.BlockCopy(uint32b, blockSizeInt32 * 4);
        }

        public byte[] DecryptBlock(byte[] block, int blockSizeInt32)
        {
            var uint32b = Decrypt(EncryptionHelper.BlockCopy(block, blockSizeInt32), key);
            return EncryptionHelper.BlockCopy(uint32b, blockSizeInt32 * 4);
        }

        public static uint[] Encrypt(uint[] b, uint[] k)
        {
            uint n = (uint)b.Length;
            uint y, z, sum;
            uint p, rounds, e;

            rounds = 6 + 52 / n;
            sum = 0;
            z = b[n - 1];
            do
            {
                sum += _Delta;
                e = (sum >> 2) & 3;
                for (p = 0; p < n - 1; p++)
                {
                    y = b[p + 1];
                    b[p] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)));
                    z = b[p];
                }
                y = b[0];
                b[n - 1] += (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)));
                z = b[n - 1];
            } while (--rounds != 0);

            return b;
        }

        public static uint[] Decrypt(uint[] b, uint[] k)
        {
            uint n = (uint)b.Length;
            uint y, z, sum;
            uint p, rounds, e;

            rounds = 6 + 52 / n;
            sum = rounds * _Delta;
            y = b[0];
            do
            {
                e = (sum >> 2) & 3;
                for (p = n - 1; p > 0; p--)
                {
                    z = b[p - 1];
                    y = b[p] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)));
                }
                z = b[n - 1];
                y = b[0] -= (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z)));
                sum -= _Delta;
            } while (--rounds != 0);

            return b;
        }
    }
}
