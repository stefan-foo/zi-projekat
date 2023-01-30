namespace Cryptography.ServiceHost.Utils
{
    public class BMPEncryption
    {
        private static readonly int BMPHeaderSize = 54;
        private bool headerReceived = false;
        public BMPEncryption() { }

        public (byte[] encBmp, byte[] key) Encrypt(byte[] bmpData)
        {
            if (!headerReceived)
            {
                if (bmpData.Length < BMPHeaderSize)
                {
                    throw new ArgumentException("Bitmap header mora biti poslat odjedanput");
                }

                byte[] encBmp = new byte[bmpData.Length];
                Array.Copy(bmpData, 0, encBmp, 0, BMPHeaderSize);

                var (encData, key) = OneTimePad.Encrypt(GetBMPData(bmpData));
                Array.Copy(encData, 0, encBmp, BMPHeaderSize, encBmp.Length - BMPHeaderSize);

                var paddedKey = new byte[bmpData.Length];
                Array.Copy(key, 0, paddedKey, BMPHeaderSize, key.Length);
                
                headerReceived = true;
                return (encBmp, paddedKey);
            }

            return OneTimePad.Encrypt(bmpData);
        }

        public byte[] Decrypt(byte[] encBmpData, byte[] key)
        {
            // Kljuc je padovan sa nulama na mestu bajtova headera, dekripcija radi i bez naredne if gane
            if (!headerReceived)
            {
                if (encBmpData.Length < BMPHeaderSize)
                {
                    throw new ArgumentException("Bitmap header mora biti poslat odjedanput");
                }

                byte[] bmp = new byte[encBmpData.Length];
                Array.Copy(encBmpData, 0, bmp, 0, BMPHeaderSize);

                var keyPadRm = new byte[encBmpData.Length - BMPHeaderSize];
                Array.Copy(key, BMPHeaderSize, keyPadRm, 0, keyPadRm.Length);

                var data = OneTimePad.Decrypt(GetBMPData(encBmpData), keyPadRm);
                Array.Copy(data, 0, bmp, BMPHeaderSize, bmp.Length - BMPHeaderSize);

                headerReceived = true;
                return bmp;
            }

            return OneTimePad.Decrypt(encBmpData, key);
        }
        public byte[] GetBMPData(byte[] bmp)
        {
            byte[] data = new byte[bmp.Length - BMPHeaderSize];
            Array.Copy(bmp, BMPHeaderSize, data, 0, data.Length);
            return data;
        }
        public byte[] GetBMPHeader(byte[] bmp)
        {
            byte[] header = new byte[BMPHeaderSize];
            Array.Copy(bmp, BMPHeaderSize, header, 0, header.Length);
            return header;
        }
    }
}
