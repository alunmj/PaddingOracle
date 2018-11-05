using System;

namespace PadOracle
{
    class Program
    {
        static void Main(string[] args)
        {
            // TODO: Add parameters for different frequency trial sequences. English - other language?
            //       JSON, XML, what else?
            // TODO: Add processing for other encodings? [What encodings?]
            // TODO: Parameter to choose what the padding error looks like (we accept any error status, or the string "paddingexception").
            // TODO: Cookies, UserAgent, AuthZ header, POST with content, custom headers, interrupt/resume
            // TODO: Logging input & output; interrupt / resume.
            string baseUrl = null, cipherReg = null, ivReg = null;
            string encryptMe = null;
            int blocksize = 16;
            bool bShowStats = false;
            int parallelism = -1;
            POEncoding encoding = POEncoding.b64;
            try
            {
                for (int i = 0; i < args.Length; i++)
                {
                    string flag = null;
                    if (args[i][0] == '-' && args[i].Length > 1)
                    {
                        if (args[i][1] == '-')
                        {
                            flag = args[i].Substring(2).ToLower();
                        }
                        else
                        {
                            flag = args[i].Substring(1).ToLower();
                        }
                    }

                    bool bLastArg = args.Length == i + 1;
                    bool bMaybeParameter = !bLastArg && args[i + 1][0] != '-';
                    switch (flag)
                    {
                        default: // No option specified, this must be the base URL.
                            baseUrl = args[i];
                            // TODO: Validate that this looks like a URL we can use. Right now, we assume this'll trigger a later exception.
                            break;
                        case "c":
                        case "cipher":
                            if (bMaybeParameter)
                            {
                                // TODO: slightly more sophisticated check for what a valid ciphertext is.
                                cipherReg = args[++i];
                            }
                            else
                            {
                                throw new ArgumentException("-c requires a following parameter that's a regex for the ciphertext in the base URL.");
                            }
                            break;
                        case "i":
                        case "iv":
                            if (bMaybeParameter)
                            {
                                ivReg = args[++i];
                            }
                            else
                            {
                                throw new ArgumentException("-i requires a following parameter that's a regex for the iv in the base URL");
                            }
                            break;
                        case "0":
                        case "iv0":
                        case "noiv":
                            ivReg = "0"; // Special 'magic' value for all-zeroes IV.
                            break;
                        case "b":
                        case "blocksize":
                            if (!bMaybeParameter || !int.TryParse(args[++i], out blocksize))
                            {
                                throw new ArgumentException("-b requires a blocksize - normally 16, 32, etc");
                            }
                            break;
                        case "t":
                        case "textencoding":
                        case "encoding":
                            if (!bMaybeParameter || !Enum.TryParse<POEncoding>(args[++i], out encoding))
                            {
                                throw new ArgumentException("I'm not able to recognise that encoding type as one that I know.");
                            }
                            break;
                        case "e":
                        case "encrypt":
                            if (!bMaybeParameter)
                            {
                                throw new ArgumentException("-e requires a parameter of the string to encrypt!");
                            }
                            encryptMe = args[++i];
                            break;
                        case "v":
                        case "verbose":
                            bShowStats = true;
                            break;
                        case "p":
                        case "parallelism":
                            if (!bMaybeParameter || !int.TryParse(args[++i], out parallelism))
                            {
                                throw new ArgumentException("-p requires an integer parameter of maximum number of threads. -1 (max parallelism) and 1 (no parallelism) are good values.");
                            }
                            break;
                        case "h":
                        case "help":
                            // Something a bit more than the usage message.
                            Console.WriteLine(@"PadOracle - padding oracle tool from alun@texis.com

Some encryption algorithms are vulnerable to padding oracle attacks. If that's
the case for your endpoint, this tool may be of use in attacking it.
I use this for CTFs (Capture The Flag), but there are also pen-test uses and
even some malicious uses. Don't use this tool maliciously, that's not its
designed purpose. Use it to win encryption-related CTF challenges, to exploit
sites that you have been given permission to do so, and to demonstrate, and
learn about, the failures of encryption that we cause.

The main parameter for this program is the URL we're going to connect to.
All other parameters have option names to indicate which parameter you're
setting.

Example:
padoracle ""http://localhost:31140/api/encrypted/submit?iv=A1BjZIyXQ1gOsWiUbaj3Kw%3d%3d&ciphertext=DUCLQSPu7788k6Xeijl6o3Xdhh%2ft%2b0V1QRpVkJF0Z7B8787y7LpbSe6iDUERWnGxc7sap3qLO1XNae0MhjlenhdEc64fi6dmtmJl8bM0nuVJmV%2f8LRfZ4%2fW%2f3FFusuvsAwoMU%2fwvaPYSvNZmxfnck5DgcL5PlXG68xGEX8usqZ1cORe8zyzh50Hoj446%2f4386OMr7%2fPA9%2bpars6L7zVvag%3d%3d"" -t b64 -c DUCLQSP.*Vvag%3d%3d -i A1BjZIyXQ1gOsWiUbaj3Kw%3d%3d

Note that the URL is in quotes, because of the ""&"" character, which would
otherwise cause issues.
Other parameters here:
-t b64                  - encoding type is base64, URL encoded
-c DUCLQSP.*Vvag%3d%3d  - cipher text regex begins 'DUCLQSP', ends 'Vvag%3d%3d'.
-i A1Bj...              - Initialisation vector is provided in full, rather than as a regex

Encoding types:
b64 - base64, URL-encoded
b64URL - URL-safe base64 (uses '!', '-', and '~' instead of '/', '+', '=') - not URL-encoded
hex - lower-case hex
HEX - upper-case hex
");
                            // Maybe one day, NET64 - base64, but with '_', '-', and ending in a count of how many '=' chars.
                            Environment.Exit(0); // Quit without doing!
                            break;
                    }
                }
                // Check for required arguments
                if (baseUrl == null)
                {
                    throw new ArgumentException("No base URL supplied - I won't know where to send my encryption attempts");
                }
                if (cipherReg == null)
                {
                    throw new ArgumentException("No cipher regex supplied - not sure which part of the URL is ciphertext");
                }
                // Defaults: encoding is base64; blocksize is 16; iv is the first block of the ciphertext.
                // -1 for parallelism, so lots of parallel
            }
            catch (ArgumentException x)
            {
                Console.WriteLine(x.Message);
                Usage();
                Environment.Exit(1); // Quit
            }

            UrlParser parser = new UrlParser(baseUrl, cipherReg, ivReg, blocksize, encoding);
            CryptTarget target = new CryptTarget(parser);
            target.ParallelThreads = parallelism;
            target.Verbose = bShowStats;
            if (encryptMe == null)
            {
                Console.WriteLine("Beginning decryption of ciphertext. This may take some time.");
                string decrypted = target.Decrypt();
                Console.WriteLine($"Decrypted string is:\n{decrypted}");
            }
            else
            {
                Console.WriteLine("Beginning decryption of ciphertext. This may take a very long time.");
                string encrypted = target.Encrypt(encryptMe);
                Console.WriteLine($"Encrypted string in URL is:\n{encrypted}");
            }
            Environment.Exit(0); // Quit.

        }

        private static void Usage()
        {
            Console.Error.WriteLine("Error in some of the parameters.\n" +
                "Typical usage: PadOracle http://<url>:<port>/path/path/path/?c=<ciphertext>[&iv=<iv>] -c <cipher-text-regex> [-i <iv-text-regex>] -t <encoding:b64|b64URL|hex> [-e \"<Text to encrypt>\"] [-p <parallelism:-1|1|#>] [-h]" +
                "\n\n-c/-ciphertext - A .NET regular expression matching the ciphertext in the URL." +
                "\n-i/-iv - [optional] A .NET regular expression matching the initialisation vector." +
                "\n-t/-textencoding/encoding - [optional] Encoding type - b64, b64URL, hex" +
                "\n-e/-encrypt - [optional] - instead of decrypting, encrypt the provided string" +
                "\n-p/-parallelism - [optional] - MaxDegreeOfParallelism. -1 to use all CPUs, 1 to use 1." +
                "\n-h/-help - [optional] - display slightly more detailed help." +
                "\n\nContact alun@texis.com with questions about this tool.");
        }

    }
}
