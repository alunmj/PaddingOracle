using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace WebAPI.Controllers
{
    public class encText
    {
        public string iv { get; set; }
        public string ciphertext { get; set; }
    }
    [Produces("application/json")]
    public class EncryptedController : Controller
    {
        public const string encKey = "Needsa16bytekey.";

        // GET: api/Encrypted
        [HttpGet]
        [Route("api/encrypted")]
        public encText Get()
        {
            byte[] encrypted;
            byte[] iv;
            string baseText = @"Here's a simple piece of text that we're going to try and encryptenate.
It covers multiple lines and has a fairly large amount of text.12345678";
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(encKey);
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                var encryptor = aesAlg.CreateEncryptor();
                using (MemoryStream ms = new MemoryStream())
                using (CryptoStream cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter sw = new StreamWriter(cs))
                    {
                        sw.Write(baseText);
                    }
                    encrypted = ms.ToArray();
                }
                iv = aesAlg.IV;
            }
            return new encText() { iv = Convert.ToBase64String(iv), ciphertext = Convert.ToBase64String(encrypted) };
        }

        [HttpGet]
        [Route("api/encrypted/submit")]
        public void Get(string IV, string ciphertext)
        {
            string decrypted="";
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Encoding.UTF8.GetBytes(encKey);
                aesAlg.IV = Convert.FromBase64String(IV);
                aesAlg.Mode = CipherMode.CBC;
                aesAlg.Padding = PaddingMode.PKCS7;
                var decryptor = aesAlg.CreateDecryptor();
                using (MemoryStream ms = new MemoryStream(Convert.FromBase64String(ciphertext)))
                using (CryptoStream cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read))
                {
                    using (StreamReader sr = new StreamReader(cs))
                    {
                        decrypted = sr.ReadToEnd();
                    }
                }
            }
        }
    }
}
