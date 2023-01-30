using System.Security.Cryptography;

namespace Cryptography.ServiceHost.Utils
{
    public class OneTimePad
    {
        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            var dataCopy = (byte[])data.Clone();
            return ModEncrypt(ref dataCopy, key);
        }

        public static byte[] ModEncrypt(ref byte[] data, byte[] key)
        {
            if (data.Length > key.Length)
            {
                throw new ArgumentException("Kljuc mora biti vece ili jednake duzine od podataka koji se sifriraju");
            }

            for (int i = 0; i < data.Length; i++)
            {
                data[i] ^= key[i];
            }

            return data;
        }
        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            return Encrypt(data, key);
        }

        public static byte[] Decrypt(byte[] data, byte[] key, int numThreads)
        {
            return Encrypt(data, key, numThreads);
        }

        public static (byte[] encryptedData, byte[] key) Encrypt(byte[] data)
        {
            Random rnd = new();

            byte[] key = new byte[data.Length];

            rnd.NextBytes(key);

            return (Encrypt(data, key), key);
        }

        public static byte[] Encrypt(byte[] data, byte[] key, int numThreads)
        {
            if (data.Length > key.Length)
            {
                throw new ArgumentException("Kljuc mora biti vece ili jednake duzine od podataka koji se sifriraju");
            }
            Array.Resize(ref key, data.Length);

            byte[][] chunks = ChunkData(data, numThreads);
            byte[][] keyChunks = ChunkData(key, numThreads);
            var chunkSize = chunks[0].Length;

            byte[] result = new byte[data.Length];

            Parallel.For(0, numThreads, i =>
            {
                ModEncrypt(ref chunks[i], keyChunks[i]);
                Array.Copy(chunks[i], 0, result, i * chunkSize, chunks[i].Length);
            });

            return result;
        }

        public static byte[][] ChunkData(byte[] data, int numChunks)
        {
            int chunkSize = data.Length / numChunks;
            int leftoverBytes = data.Length % numChunks;

            byte[][] chunks = new byte[numChunks][];

            int dataIndex = 0, size;
            for (int i = 0; i < numChunks; i++)
            {
                size = chunkSize;
                if (i == numChunks - 1)
                {
                    size += leftoverBytes;
                }

                chunks[i] = new byte[size];
                Array.Copy(data, dataIndex, chunks[i], 0, size);
                dataIndex += size;
            }

            return chunks;
        }
    }
}
