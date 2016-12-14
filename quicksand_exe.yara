/* Copyright (c) 2016 Tyler McLellan  TyLabs.com
 * QuickSand.io - Document malware forensics tool
 *
 * File quicksand_exe.yara   Dec 10 2016
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
 *
 * Commercial licensing is available for the full version.
 */

rule executable_win_pe {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /MZ.{76}This program /
condition:
            1 of them
}

rule executable_win_pe_transposed {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /ZM.{76}hTsip orrgma/
condition:
            1 of them
}


rule executable_win_pe_transposed_offbyone {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "Dec 27 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = /Z.{76}ih srpgoar macnntob  eur nniD SOm do/
condition:
            1 of them
}



rule executable_win {
	meta:
		is_exe = true
		type = "win"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = "This program cannot be run in DOS mode"
		$s2 = "This program must be run under Win32"
		$s4 = "LoadLibraryA"
		$s5 = "GetModuleHandleA"
		$s6 = "GetCommandLineA"
		$s7 = "GetSystemMetrics" 
		$s8 = "GetProcAddress"
		$s9 = "CreateProcessA"
		$s10 = "URLDownloadToFileA"
		$s11 = "EnterCriticalSection"
		$s12 = "GetEnvironmentVariableA"
		$s13 = "CloseHandle"
		$s14 = "CreateFileA"
		$s15 = "URLDownloadToFileA"
		$s16 = "Advapi32.dll"
		$s17 = "RegOpenKeyExA"
		$s18 = "RegDeleteKeyA"
		$s19 = "user32.dll"
		$s20 = "shell32.dll"
		$s21 = "KERNEL32"
		$s22 = "ExitProcess"
		$s23 = "GetMessageA"
		$s24 = "CreateWindowExA"
		$s25 = {504500004C010100} // PE header
	condition:
            1 of them and not executable_win_pe
}




rule executable_win_transposed {
	meta:
		is_exe = true
		type = "win-tp"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		desc = "Transposition cipher"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"

	strings:
		$s1 = "hTsip orrgmac naon tebr nui  nOD Somed" //string.transposition cipher of This program cannot be run in DOS mode
	condition:
            1 of them and not executable_win_pe_transposed
}

rule executable_win_rtl {
	meta:
		is_exe = true
		type = "win-rtl"
		rank = 10
		revision = "100"
		date = "July 29 2015"
		desc = "Right to Left compression LZNT1"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = {2070726F6772616D002063616E6E6F74200062652072756E2069006E20444F53206D6F} // string.RTL.This program cannot be run in DOS mode
	condition:
            1 of them
}

rule executable_win_reversed {
	meta:
		is_exe = true
		type = "win-reversed"
		rank = 10
		revision = "100"
		date = "July 29 2015"
		desc = "EXE is stored backwards"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = "edom SOD ni nur eb tonnac margorp sihT" // string.reverse This program cannot be run in DOS mode	condition:
	condition:
            1 of them
}



rule executable_vb {
	meta:
		is_exe = true
		revision = "100"
		rank = 10
		type = "vb"
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = "impersonationLevel=impersonate"
		$s2 = "On Error Resume Next"
		$s3 = "WScript.CreateObject(\"WScript.Shell\")"
		$s4 = "CreateObject(\"Scripting.FileSystemObject\")"
	condition:
            1 of them
}


rule executable_macosx {
	meta:
		is_exe = true
		type = "macosx"
		revision = "100"
		rank = 10
		date = "July 29 2015"
		author = "@tylabs"
		copyright = "QuickSand.io 2015"
		tlp = "green"
	strings:
		$s1 = "<key>RunAtLoad</key>"
		$s2 = "__mh_execute_header"
		$s3 = "/Developer/SDKs/MacOSX10.5.sdk/usr/include/libkern/i386/_OSByteOrder.h"
		$s4 = "__gcc_except_tab__TEXT"
		$s5 = "/System/Library/Frameworks/CoreServices.framework/Versions/A/CoreServices"
		$s6 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation"
		$s7 = "@_getaddrinfo"
		$s8 = "@_pthread_create"
		$s9 = "StartupParameters.plist"
		$s10 = "dyld__mach_header"
		$s11 = "/usr/lib/libSystem"
		$s12 = "/usr/lib/dyld"
		$s13 = "__PAGEZERO"
		$s14 = "/usr/lib/libgcc_s"
	condition:
            1 of them
}


