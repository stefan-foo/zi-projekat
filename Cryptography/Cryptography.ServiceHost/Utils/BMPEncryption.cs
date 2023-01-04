namespace Cryptography.ServiceHost.Utils
{
    public class BMPEncryption
    {
        private static readonly int BMPHeaderSize = 54;
        public BMPEncryption() { }

        public (byte[] encBmp, byte[] key) Encrypt(byte[] bmp)
        {
            byte[] encBmp = new byte[bmp.Length];
            Array.Copy(bmp, 0, encBmp, 0, BMPHeaderSize);

            var (encData, key) = OneTimePad.Encrypt(GetBMPData(bmp));

            Array.Copy(encData, 0, encBmp, BMPHeaderSize, encBmp.Length - BMPHeaderSize);

            return (encBmp, key);
        }

        public byte[] Decrypt(byte[] encBmp, byte[] key)
        {
            byte[] bmp = new byte[encBmp.Length];
            Array.Copy(encBmp, 0, bmp, 0, BMPHeaderSize);

            var data = OneTimePad.Decrypt(GetBMPData(encBmp), key);

            Array.Copy(data, 0, bmp, BMPHeaderSize, bmp.Length - BMPHeaderSize);

            return bmp;
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
