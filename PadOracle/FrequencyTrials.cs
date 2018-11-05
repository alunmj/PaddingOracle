using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace PadOracle
{
    class FrequencyTrials
    {
        public static IEnumerable<byte> Sequence => Enumerable.Range(0, 256).Select(x => (byte)x);
    }
    class PaddingFrequency32 : FrequencyTrials
    {
        static private byte[] baseSequence = new byte[]
        {
            0x20,0x1f,0x1e,0x1d,0x1c,0x1b,0x1a,0x19,0x18,0x17,0x16,0x15,0x14,0x13,0x12,0x11,
            0x10,0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,0x07,0x06,0x05,0x04,0x03,0x02,0x01
        };
        public static new IEnumerable<byte> Sequence => baseSequence;
    }
    class EnglishFrequency : FrequencyTrials
    {
        static private byte[] baseSequence = null;
        public static new IEnumerable<byte> Sequence
        {
            get
            {
                if (baseSequence == null)
                {
                    baseSequence = new byte[256];
                    string charfreq = "etaonishrlducmwyfgpbvkjxqzETAONISHRLDUCMWYFGPBVKJXQZ,. -'_?:()!0123456789\n\r{}~/\"^$";
                    UTF8Encoding.UTF8.GetBytes(charfreq).CopyTo(baseSequence, 0);
                    int j = charfreq.Length;
                    // Fill in the rest of the bytes, in case there's a character we didn't think of.
                    for (int i = 0; i < 256; i++)
                    {
                        if (!charfreq.Contains((char)i))
                        {
                            baseSequence[j++] = (byte)i;
                        }
                    }
                    // We got all the bytes exactly once, yes?
                    System.Diagnostics.Debug.Assert(j == 256);

                }
                return baseSequence;
            }
        }
    }
}
