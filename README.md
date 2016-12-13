
# QuickSand.io
<img width=200 height=200 src=https://repo.quicksand.io/quicksand.png>
<img src="https://quicksand.io/images/quicksand.png" border=0 height=200>

QuickSand is a compact C framework to analyze suspected malware documents to 1) identify exploits in streams of different encodings, 2) locate and extract embedded executables. By having the ability to locate embedded obfuscated executables, QuickSand could detect documents that contain zero-day or unknown obfuscated exploits.

## File Formats For Exploit and Active Content

- doc, docx, rtf, etc
- ppt, pptx, etc
- xls, xlsx, etc
- mime mso


## File Formats For Executable Detection

- All of the above, plus PDF.
- Any document format.


## Lite Version - Mplv2 License

- Key dictionary up to 256 byte XOR
- ROL, ROR, NOT
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
- Yara signatures included: Executables, exploits and active content


## Full Version - Commercial License

- Key cryptanalysis 1-1024 bytes factors of 2; or a specified odd size
- 1 Byte zerospace not replaced brute force search
- XOR Look Ahead
- Yara signatures included: Executables, most recent exploits and active content
- Try the full version online at [QuickSand.io](https://quicksand.io/)


# Dependencies

- Yara 3+
- zlib
- libzip


# Documentation

[QuickSand.io](https://quicksand.io/)


# Copyright, License, and Trademark

QuickSand.io and the QuickSand application logo are Copyright 2016 Tyler McLellan  Tylabs. 

quicksand.c, libqs.h and libqs.c are Copyright 2016 Tyler McLellan  Tylabs.


See included Mozilla Public License Version 2.0 for licensing information.
