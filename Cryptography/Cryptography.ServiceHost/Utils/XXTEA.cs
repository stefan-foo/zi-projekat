using System.Text;

namespace Cryptography.ServiceHost.Utils
{
    public class XXTEA
    {
        private static readonly uint Delta = 0x9e3779b9;
        private static readonly int _BlockSize = 1024;
        private readonly uint[] key = new uint[4];

        public XXTEA(byte[] key)
        {
            EncryptionHelper.ByteToUint32Array(key, this.key);
        }

        public XXTEA(string key) : this(Encoding.UTF8.GetBytes(key))
        {
        }

        public static int BlockSize
        {
            get { return _BlockSize; }
        }

        public byte[] EncryptBlock(byte[] block)
        {
            uint[] uint32Block = EncryptionHelper.ByteToUint32Array(block, _BlockSize);

            Encrypt(uint32Block, key);

            byte[] encryptedData = new byte[_BlockSize * 4];

            Buffer.BlockCopy(uint32Block, 0, encryptedData, 0, encryptedData.Length);
            return encryptedData;
        }
        public byte[] DecryptBlock(byte[] block)
        {
            uint[] uint32Block = EncryptionHelper.ByteToUint32Array(block, _BlockSize);

            Decrypt(uint32Block, key);

            byte[] decryptedData = new byte[_BlockSize * 4];

            Buffer.BlockCopy(uint32Block, 0, decryptedData, 0, decryptedData.Length);
            return decryptedData;
        }
        public static byte[] Encrypt(byte[] block, byte[] key)
        {
            uint[] dataUint32 = new uint[_BlockSize];

            Buffer.BlockCopy(block, 0, dataUint32, 0, block.Length);

            uint[] data = Encrypt(dataUint32, EncryptionHelper.ByteToUint32Array(key, 4));

            byte[] encryptedData = new byte[_BlockSize * 4];

            Buffer.BlockCopy(data, 0, encryptedData, 0, encryptedData.Length);
            return encryptedData;
        }
        public static byte[] Decrypt(byte[] block, byte[] key)
        {
            uint[] dataUint32 = new uint[_BlockSize];

            Buffer.BlockCopy(block, 0, dataUint32, 0, block.Length);

            uint[] data = Decrypt(dataUint32, EncryptionHelper.ByteToUint32Array(key, 4));

            byte[] decryptedData = new byte[_BlockSize * 4];

            Buffer.BlockCopy(data, 0, decryptedData, 0, decryptedData.Length);
            return decryptedData;
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
                sum += Delta;
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
            sum = rounds * Delta;
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
                sum -= Delta;
            } while (--rounds != 0);

            return b;
        }
    }
}
