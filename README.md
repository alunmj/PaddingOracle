# PaddingOracle
Source code for a Padding Oracle attack demonstration - vulnerable API and cracking code. C#, ASP .NET

This was written after a hacking challenge (CTF / "Hackathon") at work.

Build the WebAPI project, then run it without debugging, so that you can then debug the PadOracle project against it.

Change the string as you want, to discover how well it does/doesn't work. Try to throw the algorithm off.

See if there are any optimisations you can think of. It's still very slow, perhaps.

Command line arguments are now added in the PadOracle program:

PadOracle &lt;url> -c &lt;cipher-reg> [-i &lt;iv-reg>] [-iv0] [-b &lt;blocksize:16>] [-t &lt;encoding:b64|b64URL|hex|HEX>] [-v] [-p &lt;parallelism:-1|1>] [-h]<br/>
&nbsp;&nbsp;&lt;cipher-reg>: a regex matching the entire ciphertext in the &lt;url> parameter<br/>
&nbsp;&nbsp;&lt;iv-reg>: a regex matching the initialisation vector in the &lt;url> parameter, if separate<br/>
&nbsp;&nbsp;&lt;blocksize>: blocksize in bytes. Defaults to 16.<br/>
&nbsp;&nbsp;&lt;encoding>: The encoding of the ciphertext. b64 = base64, URL encoded; b64URL = base64 URL safe (/, +, =, replaced with !, -, ~); hex / HEX - hexadecimal encoded, lower / upper case.<br/>
&nbsp;&nbsp;&lt;parallelism>: How parallel do you want it? 1 is for 1 thread, so you can watch it work. -1 is for max parallel, more speed. Defaults to -1.<br/>
    
