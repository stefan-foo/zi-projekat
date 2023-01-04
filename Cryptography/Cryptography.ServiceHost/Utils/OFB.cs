using Google.Protobuf;

namespace Cryptography.ServiceHost.Utils
{
    public class OFB
    {
        private byte[] iV = new byte[XXTEAfbs.BlockSizeUint32 * 4];
        readonly XXTEAfbs _XXTEAfbs;

        private readonly byte[] buffer = new byte[XXTEAfbs.BlockSizeUint32 * 4];
        private int bi = 0;
        public OFB(byte[] iV, byte[] key)
        {
            if (iV.Length < XXTEA.BlockSize * 4)
            {
                throw new ArgumentException($"Inicijalizacioni vektor mora biti duzine najmanje {XXTEAfbs.BlockSizeUint32} bajtova");
            }

            _XXTEAfbs = new XXTEAfbs(key);
            Buffer.BlockCopy(iV, 0, this.iV, 0, XXTEAfbs.BlockSizeUint32 * 4);
        }

        public bool Empty {
            get { return bi == 0; }
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
                    iV = _XXTEAfbs.EncryptBlock(iV, XXTEAfbs.BlockSizeUint32);
                    yield return OneTimePad.Encrypt(buffer, iV);
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
                    iV = _XXTEAfbs.EncryptBlock(iV, XXTEAfbs.BlockSizeUint32);
                    var decrypted = OneTimePad.Decrypt(buffer, iV);


                    yield return EncryptionHelper.RemovePadding(decrypted);
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

        public byte[] EncryptBlock(byte[] data, byte[] iV)
        {
            iV = _XXTEAfbs.EncryptBlock(iV, XXTEAfbs.BlockSizeUint32);
            return OneTimePad.Encrypt(data, iV);
        }

        public byte[] DecryptBlock(byte[] data, byte[] iV)
        {
            iV = _XXTEAfbs.EncryptBlock(iV, XXTEAfbs.BlockSizeUint32);
            return OneTimePad.Decrypt(data, iV);
        }
    }
}
