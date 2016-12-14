/* 
 * QuickSand.io - Document malware forensics tool
 *
 * File  quicksand_general.yara  Dec 10 2016
 * Original source code available from https://github.com/tylabs/quicksand_lite
 * 
 * Decode and look in streams of Office Documents, RTF, MIME MSO.
 * XOR Database attack up to 256 byte keys to find embedded exe's.
 * Lite version - doesn't include cryptanalysis module and latest Office CVEs
 * Web version at http://quicksand.io/ has full features.
 *
 * Unless noted within the signature, signatures are subject to the terms
 * of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 */

rule doc_exploit_ms12_060_toolbar
{
	meta:
		author = "@tylabs"
	strings:
		$a = "MSComctlLib.Toolbar.2"
		$b = {4D53436F6D63746C4C69622E546F6F6C6261722E32}
	condition:
		any of them
}


rule winrar_sfx {
	meta:
		author = "@tylabs"
	strings:
		$u1 = "d:\\Projects\\WinRAR\\SFX\\build\\sfxrar32\\Release\\sfxrar.pdb"
	condition:
		any of them
}


rule this_alt_key
{
	meta:
		author = "@tylabs"
		hash = "821f7ef4349d542f5f34f90b10bcc690"
	strings:
		$a = {79 BA 1E 6F E1 16 79 DF 32 88 FE 29 C9 ED 52 B6 13 4D B3 4C 73 D3 7B 72 D0 24 CF FD 57 FE C7 67 9E 52 7A D3 05 63}
	condition:
		any of them
}

rule this_dbl_xor
{
	meta:
		author = "@tylabs"
		hash = "d85d54434e990e84a28862523c277057"
	strings:
		$a = {86 BB BD A6 F6 A7 5A 46 4D 59 4D 40 0E 4C 41 4F 4C 4C 50 05 44 42 18 4B 4F 55 1C 54 50 1F 74 7E 61 13 59 5A 52 52 }
	condition:
		any of them
}

rule gen_ie_secrets {
	meta:
		author = "@tylabs"
 	strings:
 		$a = "abe2869f-9b47-4cd9-a358-c22904dba7f7"
 	condition:
 		all of them
}

rule compiler_midl
{
	meta:
		author = "@tylabs"

        strings:
		$s1 = "Created by MIDL version " wide
	condition:
		any of them
}



rule compression_ucl
{
	meta:
		author = "@tylabs"
        strings:
                $s1 = "UCL data compression library." wide
		$s2 = "Id: UCL version:" wide
	condition:
		all of them
}

rule coms_openssl
{
	meta:
		author = "@tylabs"
	strings:
                $s1 = ".\\ssl\\ssl_lib.c"
		$s2 = ".\\ssl\\ssl_sess.c"
		$s3 = "part of OpenSSL"
	condition:
		all of them
}




rule netcat
{
	meta:
		author = "@tylabs"
    		comment = "tool"

	strings:
    		$a = "Failed to create ReadShell session thread, error = %s"
    		$b = "Failed to create shell stdout pipe, error = %s"
 
	condition:
   		all of them 
}


rule apt_template_tran_duy_linh
{
	meta:
		author = "@tylabs"
          	info = "author"
	strings:
		$auth = { 4E 6F 72 6D 61 6C 2E 64 6F 74 6D 00 1E 00 00 00 10 00 00 00 54 72 61 6E 20 44 75 79 20 4C 69 6E 68 }

	condition:
		$auth
}

rule theme_MH370 {
	meta:
		author = "@tylabs"
		version = "1.0"
		date = "2014-04-09"
	strings:
		$callsign1 = "MH370" ascii wide nocase fullword
		$callsign2 = "MAS370" ascii wide nocase fullword
		$desc1 = "Flight 370" ascii wide nocase fullword

	condition:
		any of them
}

rule theme_MH17 {
	meta:
		author = "@tylabs"
		version = "1.0"
		date = "2014-04-09"
	strings:
		$callsign1 = "MH17" ascii wide nocase fullword
		$callsign2 = "MAS17" ascii wide nocase fullword
		$desc1 = "malaysia airlines flight 17" ascii wide nocase

	condition:
		any of them
}



rule openxml_remote_content
{
	meta:
		author = "@tylabs"
		ref = "https://www.defcon.org/html/defcon-22/dc-22-speakers.html#Crenshaw"
		date = "Aug 10 2014"
		hash = "63ea878a48a7b0459f2e69c46f88f9ef"

	strings: 
		$a = "schemas.openxmlformats.org" ascii nocase
		$b = "TargetMode=\"External\"" ascii nocase

	condition:
		all of them
}


rule office97_guid
{
	meta:
		author = "@tylabs"
		ref = "http://search.lores.eu/fiatlu/GUIDnumber.html"
		
	strings:
		$a = "_PID_GUID"
		$magic = {D0 CF 11 E0}

	condition:
		$magic at 0 and $a
}

rule InceptionRTF {
	meta: 
		author = "Blue Coat Systems, Inc"
		reference = "http://goo.gl/qr7BP4"
		date = "12/10/2014"
		description = "Used by unknown APT actors: Inception"
	strings:
		$a = "}}PT@T"
		$b = "XMLVERSION \"3.1.11.5604.5606"
		$c = "objclass Word.Document.12}\\objw9355" 
	condition:
		all of them
}

rule mime_mso
{
	meta:
		author = "@tylabs"
		comment = "mime mso detection"
	strings:
		$a="application/x-mso"
		$b="MIME-Version"
		$c="ocxstg001.mso"
		$d="?mso-application"
	condition:
		$a and $b or $c or $d
}


rule mime_mso_embedded_SuppData
{
	meta:
		author = "@tylabs"
    		comment = "mime mso office obfuscation"
    		hash = "77739ab6c20e9dfbeffa3e2e6960e156"
		date = "Mar 5 2015"

	strings:
		$a = "docSuppData"
		$b = "binData"
		$c = "schemas.microsoft.com"

	condition:
		all of them
}


rule mime_mso_embedded_ole
{
	meta:
		author = "@tylabs"
    		comment = "mime mso office obfuscation"
    		hash = "77739ab6c20e9dfbeffa3e2e6960e156"
		date = "Mar 5 2015"

	strings:
    		$a = "docOleData"
    		$b = "binData"
    		$c = "schemas.microsoft.com"
 
	condition:
    		all of them
}




rule mime_mso_vba_macros
{
	meta:
		author = "@tylabs"
		comment = "mime mso office obfuscation"
		hash = "77739ab6c20e9dfbeffa3e2e6960e156"
		date = "Mar 5 2015"

	strings:
		$a = "macrosPresent=\"yes\""
		$b = "schemas.microsoft.com"

	condition:
		all of them
}

rule ExOleObjStgCompressedAtom { 
	meta:
		author = "@tylabs"
		date   = "2015 06 09"
		ref    = "http://www.threatgeek.com/2015/06/fidelis-threat-advisory-1017-phishing-in-plain-sight.html"
		hashes = "2303c3ad273d518cbf11824ec5d2a88e"
	strings: 
		$head = { 10 00 11 10 }
		$magic = { D0 CF 11 E0 }
		$openxml = "Package0" wide
	
	condition:
		($magic at 0) and $head and $openxml
}



rule office_encryption { 
	meta:
		author = "@tylabs"
		date   = "2015 06 22"
	strings: 
		$sig1 = "Microsoft Base Cryptography Provider v" wide
		$sig2 = "EncryptedSummary" wide
		$magic = { D0 CF 11 E0 }
	
	condition:
		($magic at 0) and (1 of ($sig*))

}

