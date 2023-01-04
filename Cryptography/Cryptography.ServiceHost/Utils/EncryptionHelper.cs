namespace Cryptography.ServiceHost.Utils
{
    public static class EncryptionHelper
    {
        public static void ByteToUint32Array(byte[] sourceArray, uint[] destArray)
        {
            int uint32ArraySize = sourceArray.Length / 4;

            for (int i = 0; i < Math.Min(uint32ArraySize, destArray.Length); i++)
            {
                destArray[i] = (uint)(sourceArray[i * 4] << 24);
                destArray[i] |= (uint)(sourceArray[i * 4 + 1] << 16);
                destArray[i] |= (uint)(sourceArray[i * 4 + 2] << 8);
                destArray[i] |= (uint)(sourceArray[i * 4 + 3]);
            }
        }

        public static uint[] BlockCopy(byte[] srcArray, int dstLength)
        {
            uint[] block = new uint[dstLength];
            Buffer.BlockCopy(srcArray, 0, block, 0, Math.Min(srcArray.Length, dstLength * 4));
            return block;
        }

        public static byte[] BlockCopy(uint[] srcArray, int dstLength) { 
            byte[] block = new byte[dstLength];
            Buffer.BlockCopy(srcArray, 0, block, 0, Math.Min(dstLength, srcArray.Length * 4));
            return block;
        }

        public static uint[] ByteToUint32Array(byte[] sourceArray, int uint32ArraySize)
        { 
            int fullInts = sourceArray.Length / 4;

            uint[] destArray = new uint[uint32ArraySize];

            int i;
            for (i = 0; i < Math.Min(fullInts, uint32ArraySize); i++)
            {
                destArray[i] = (uint)(sourceArray[i * 4] << 24) | 
                    (uint)(sourceArray[i * 4 + 1] << 16) | 
                    (uint)(sourceArray[i * 4 + 2] << 8)  | 
                    (uint)(sourceArray[i * 4 + 3]);
            }

            if (sourceArray.Length % 4 != 0 && uint32ArraySize + 1 > fullInts)
            {
                if (i < sourceArray.Length) 
                    destArray[fullInts] =  (uint)(sourceArray[i] << 24);
                i++;
                if (i < sourceArray.Length)
                    destArray[fullInts] |= (uint)(sourceArray[i] << 16);
                i++;
                if (i < sourceArray.Length)
                    destArray[fullInts] |= (uint)(sourceArray[i] << 8);
            }

            return destArray;
        }

        public static byte[] RemovePadding(byte[] block)
        {
            var size = block.Length;
            var i = size - 1;

            if (block[i] == 0x80)
            {
                size = i;
            }
            else if (block[i] == 0)
            {
                while (i > 0 && block[i] == 0) i--;

                if (block[i] == 0x80)
                {
                    size = i;
                }
            }

            Array.Resize(ref block, size);
            return block;
        }
    }
}
