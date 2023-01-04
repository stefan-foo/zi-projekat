using System.Security.Cryptography;

namespace Cryptography.ServiceHost.Utils
{
    public class OneTimePad
    {
        public static byte[] Encrypt(byte[] data, byte[] key)
        {
            if (data.Length > key.Length)
            {
                throw new ArgumentException("Kljuc mora biti vece ili jednake duzine od podataka koji se sifriraju");
            }

            byte[] encryptedData = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                encryptedData[i] = (byte)(data[i] ^ key[i]);
            }

            return encryptedData;
        }

        public static byte[] Decrypt(byte[] data, byte[] key)
        {
            return Encrypt(data, key);
        }

        public static (byte[] encryptedData, byte[] key) Encrypt(byte[] data)
        {
            Random rnd = new();

            byte[] key = new byte[data.Length];

            rnd.NextBytes(key);

            return (Encrypt(data, key), key);
        }
    }
}
