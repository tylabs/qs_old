
# QuickSand.io
<img width=200 height=200 src=https://repo.quicksand.io/quicksand.png>
<img src="https://quicksand.io/images/quicksand.png" border=0 height=200>

QuickSand is a compact C framework to analyze suspected malware documents to 1) identify exploits in streams of different encodings, 2) locate and extract embedded executables. By having the ability to locate embedded obfuscated executables, QuickSand could detect documents that contain zero-day or unknown obfuscated exploits.

## File Formats For Exploit and Active Content Detection

- doc, docx, docm, rtf, etc
- ppt, pptx, pps, ppsx, etc
- xls, xlsx, etc
- mime mso
- eml email

## File Formats For Executable Detection

- All of the above, plus PDF.
- Any document format such as HWP.


## Lite Version - Mplv2 License

- Key dictionary up to 256 byte XOR
- Bitwise ROL, ROR, NOT
- Addition or substraction math cipher
- Executable extraction: Windows, Mac, Linux, VBA
- Exploit search
- RTF pre processing
- Hex stream extract
- Base 64 Stream extract
- Embedded Zip extract
- ExOleObjStgCompressedAtom extract
- zLib Decode
- Mime Mso xml Decoding
- OpenXML decode (unzip)
- Yara signatures included: Executables, active content, exploits CVE 2014 and earlier

Example results and more info [blog post](http://blog.malwaretracker.com/2016/12/quicksandio-open-source-version-released.html)


## Full Version - Commercial License

- Key cryptanalysis 1-1024 bytes factors of 2; or a specified odd size 1-1024 bytes
- 1 Byte zerospace not replaced brute force XOR search
- XOR Look Ahead cipher
- More Yara signatures included: All lite plus most recent exploits 2014-2016 for CVE identification
- Try the full version online at [QuickSand.io](https://quicksand.io/)


## Dependencies (not included)

- Yara 3.4+
- zlib 1.2.1+
- libzip 1.1.1+


## Distributed components under their own licensing

- MD5 by RSA Data Security, Inc.
- SHA1 by Paul E. Jones
- SHA2 by Aaron D. Gifford 
- jWrite by TonyWilk for json output
- tinydir by Cong Xu, Baudouin Feildel for directory processing


## Quick Start
- ./build.sh
- ./quicksand.out -h
- ./quicksand.out malware.doc


## Documentation

[QuickSand.io](https://quicksand.io/)


## Copyright, License, and Trademark

"QuickSand.io" name and the QuickSand application logo are Copyright 2016 Tyler McLellan and Tylabs and their use requires written permission from the author.

Source code quicksand.c, libqs.h, libqs.c and the yara signatures except where noted are Copyright 2016 Tyler McLellan and Tylabs.

See included Mozilla Public License Version 2.0 for licensing information.
