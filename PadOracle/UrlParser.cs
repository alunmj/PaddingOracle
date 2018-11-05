using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;

namespace PadOracle
{
    public class UrlParser
    {
        private byte[] _originalCipher;
        private readonly bool _bSeparateIV;
        private string _strUrlFormat; // e.g. "http://localhost:3001/path/api/decrypt?cipher={0}&iv={1}";

        private readonly int _blocksize;
        private byte[] _ciphertext;
        private readonly POEncoding _encoding;
        private int _blockCount = 0;
        public int BlockCount
        {
            get
            {
                if (_blockCount == 0) { _blockCount = _originalCipher.Length / _blocksize; }
                return _blockCount;
            }
        }
        public UrlParser(string baseUrl,
            string cipherReg,
            string ivReg,
            int blocksize,
            POEncoding encoding)
        {
            _blocksize = blocksize;
            string ivString = null, cipherString;
            _bSeparateIV = true;
            _encoding = encoding;
            if (String.IsNullOrEmpty(cipherReg))
            {
                throw new ArgumentException("I don't know where to phind the ciphertext.");
            }
            Regex reCipher = new Regex(cipherReg);
            MatchCollection matches = reCipher.Matches(baseUrl);
            if (matches.Count < 1)
            {
                throw new ArgumentException("I can't find any occurrences of the ciphertext in the URL you gave me. Is your regex busted?");
            }
            if (matches.Count > 1)
            {
                throw new ArgumentException("I found more than one section of the URL that matches the ciphertext you provided. I can't work like that!");
            }
            cipherString = matches[0].Value;

            if (!String.IsNullOrEmpty(ivReg))
            {
                if (ivReg.Equals("0")) // Special "magic" value.
                {
                    ivString = EncodeCipher(new byte[_blocksize]); // All zeroes.
                }
                else
                {
                    Regex reIV = new Regex(ivReg);
                    matches = reIV.Matches(baseUrl);
                    // It's OK not to find the IV, it means the IV is supplied explicitly and isn't in the URL.
                    if (matches.Count > 1) // This isn't OK.
                    {
                        throw new ArgumentException("I found more than one section of the URL that matches the IV you provided. That won't work.");
                    }
                    else if (matches.Count == 1)
                    {
                        ivString = matches[0].Value;
                    }
                }
            }

            if (!String.IsNullOrEmpty(ivString))
            {
                _strUrlFormat = baseUrl.Replace(cipherString, "{0}").Replace(ivString, "{1}"); // It's OK if ivString isn't in baseUrl!
                _originalCipher = DecodeCipher(ivString).Concat(DecodeCipher(cipherString)).ToArray();
            }
            else
            {
                _bSeparateIV = false;
                _strUrlFormat = baseUrl.Replace(cipherString, "{0}");
                _originalCipher = DecodeCipher(cipherString);
            }
            Reset();
        }
        public void Reset() { _ciphertext = (byte[])_originalCipher.Clone(); } // Return to original URL.
        public byte[] CipherText
        {
            get { return _ciphertext; }
        }
        public byte[] GetCipherBlock(int blockNumber) { return _ciphertext.Skip(blockNumber * _blocksize).Take(_blocksize).ToArray(); } // return the block
        private string EncodeCipher(IEnumerable<byte> bytes) { return EncodeCipher(bytes.ToArray()); }
        private byte[] DecodeCipher(string cipherString)
        {
            byte[] retval;
            switch (_encoding)
            {
                case POEncoding.b64URL:
                    return Convert.FromBase64String(cipherString.Replace('~', '=').Replace('!', '/').Replace('-', '+'));
                case POEncoding.b64:
                    return Convert.FromBase64String(WebUtility.UrlDecode(cipherString));
                case POEncoding.hex:
                case POEncoding.HEX:
                    retval = new byte[cipherString.Length / 2];
                    for (int i = 0; i < cipherString.Length; i += 2)
                    {
                        retval[i / 2] = (byte)Convert.ToInt16(cipherString.Substring(i, 2), 16);
                    }
                    return retval;
            }
            throw new NotSupportedException("We don't support that encoding yet.");
        }
        private string EncodeCipher(byte[] bytes)
        {
            switch (_encoding)
            {
                case POEncoding.b64URL:
                    return Convert.ToBase64String(bytes).Replace('+', '-').Replace('/', '!').Replace('=', '~');
                case POEncoding.b64:
                    return WebUtility.UrlEncode(Convert.ToBase64String(bytes));
                case POEncoding.hex:
                    return BitConverter.ToString(bytes).Replace("-", "").ToLower();
                case POEncoding.HEX:
                    return BitConverter.ToString(bytes).Replace("-", "").ToUpper();
            }
            throw new NotSupportedException("We don't have support for that encoding yet");
        }

        public int BlockSize { get { return _blocksize; } }

        public string URLTest(byte[] testCipher = null) // Return the URL for a test cipher.
        {
            string returnUrl;
            if (testCipher == null)
            {
                testCipher = _ciphertext;
            }
            if (_bSeparateIV && _strUrlFormat.Contains("{1}"))
            {
                returnUrl = string.Format(_strUrlFormat, EncodeCipher(testCipher.Skip(_blocksize)), EncodeCipher(testCipher.Take(_blocksize)));
            }
            else
            {
                returnUrl = string.Format(_strUrlFormat, EncodeCipher(testCipher));
            }
            return returnUrl;
        }

        public void ClearCipher(int nBlocks)
        {
            _originalCipher = new byte[nBlocks * _blocksize];
            Reset();
        }

        public void SetCipherBlock(int nBlock, byte[] setBlock)
        {
            setBlock.CopyTo(_ciphertext, nBlock * _blocksize);
        }
    }
}
