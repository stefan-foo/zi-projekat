using System.Text;
using System.Text.RegularExpressions;

namespace Cryptography.ServiceHost.Utils
{
    public class FourSquareCypher
    {
        private static readonly int _BlockSize = 5;
        private static readonly char[,] _AlphabetBlock = new char[,] {
            { 'a', 'b', 'c', 'd', 'e' },
            { 'f', 'g', 'h', 'i', 'k' },
            { 'l', 'm', 'n', 'o', 'p' },
            { 'q', 'r', 's', 't', 'u' },
            { 'v', 'w', 'x', 'y', 'z' }
        };
        private readonly char[,] _Block0, _Block1, _Block2, _Block3;
        
        public FourSquareCypher(string key1, string key2)
        {
            key1 = Regex.Replace(key1.ToLower(), "[^a-zA-Z]", "");
            key2 = Regex.Replace(key2.ToLower(), "[^a-zA-Z]", "");

            _Block1 = StringToKeyBlock(key1);
            _Block2 = StringToKeyBlock(key2);
            _Block0 = _Block3 = _AlphabetBlock;
        }

        private static char[,] StringToKeyBlock(string key)
        {
            if (key.Length < Math.Pow(_BlockSize, 2))
            {
                throw new ArgumentException("Kljuc nedovoljne duzine");
            }

            char[,] keyBlock = new char[_BlockSize, _BlockSize];

            for (int i = 0; i < _BlockSize; i++)
            {
                for (int j = 0; j < _BlockSize; j++)
                {
                    keyBlock[i, j] = key[i * _BlockSize + j];
                }
            }

            return keyBlock;
        }

        private static (int row, int col) GetCharIndices(char[,] block, char c)
        {
            for (int i = 0; i < block.GetLength(0); i++)
            {
                for (int j = 0; j < block.GetLength(1); j++)
                {
                    if (block[i, j] == c)
                    {
                        return (i, j);
                    }
                }
            }

            return (0, 0);
        }

        private static (char, char) EncodePair(char c1, char c2, char[,] block0, char[,] block1, char[,] block2, char[,] block3)
        {
            var (row1, col1) = GetCharIndices(block0, c1);
            var (row2, col2) = GetCharIndices(block3, c2);

            return (block1[row1, col2], block2[row2, col1]);
        }

        public string Encrypt(string text)
        {
            return Encrypt(text, _Block1, _Block2);
        }

        public string Decrypt(string text)
        {
            return Decrypt(text, _Block1, _Block2);
        }

        public static string Encrypt(string text, string key1, string key2)
        {
            return Encrypt(text, StringToKeyBlock(key1), StringToKeyBlock(key2));
        }

        public static string Decrypt(string text, string key1, string key2)
        {
            return Decrypt(text, StringToKeyBlock(key1), StringToKeyBlock(key2));
        }

        public static string Encrypt(string text, char[,] key1Block, char[,] key2Block)
        {
            char c1 = 'x';
            bool first = true;

            StringBuilder sb = new();

            for (int i = 0; i < text.Length; i++)
            {
                if (Regex.IsMatch(text.Substring(i, 1), "[a-zA-Z]"))
                {
                    if (first)
                    {
                        c1 = (char)text[i];
                    }
                    else
                    {
                        var (e1, e2) = EncodePair(Char.ToLower(c1), Char.ToLower(text[i]), _AlphabetBlock, key1Block, key2Block, _AlphabetBlock);
                        sb.Append(e1);
                        sb.Append(e2);
                    }
                    first = !first;
                }
            }

            if (!first)
            {
                var (e1, e2) = EncodePair(Char.ToLower(c1), 'x', _AlphabetBlock, key1Block, key2Block, _AlphabetBlock);
                sb.Append(e1);
                sb.Append(e2);
            }

            return sb.ToString();
        } 

        public static string Decrypt(string text, char[,] key1Block, char[,] key2Block)
        {
            StringBuilder sb = new();

            for (int i = 0; i < text.Length; i+=2)
            {
                var (e1, e2) = EncodePair(Char.ToLower(text[i]), Char.ToLower(text[i+1]), key1Block, _AlphabetBlock , _AlphabetBlock, key2Block);
                sb.Append(e1);
                sb.Append(e2);
            }

            return sb.ToString();
        }
    }
}
