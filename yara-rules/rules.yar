rule WaferFamily
{
    strings:
        $signature1 = /(parseInt)(.{350,500})(parseInt)(.*)(;)/
        $signature2 = /(push)(.{,16})(shift)/
        $signature3 = "pipedream"
        $signature4 = "swipingDirection"
    condition: 
        any of them
}
rule discord_stealer 
{
    meta:
		description = "Detects the best Discord Password Stealer."
        author = "Tim Dang"
        date = "2022-09-13"
    strings: 
        $s1 = "api.deltastealer.xyz"
        $s2 = "data.new_password"
        $s3 = "data[\"card[number]\"]"
        $s4 = "passwordChanged"
        $s5 = "emailChanged"
        $s6 = "process.env.temp"
        $s7 = "deltastealer.xyz"
        $s8 = "https://discord.com/api/v*/users/@me"
        $s9 = "https://discordapp.com/api/v*/users/@me"
        $s10 = "https://*.discord.com/api/v*/users/@me"
        $s11 = "https://discordapp.com/api/v*/auth/login"
        $s12 = "https://discord.com/api/v*/auth/login"
        $s13 = "https://*.discord.com/api/v*/auth/login"
        $s14 = "https://api.stripe.com/v*/tokens"
    condition:
        3 of them
}

rule contact_search
{
    strings:
        $s1 = "heyhtm+1@wearehackerone.com"
        $s2 = "commercialsalesandmarketing/contact-search"
        $s3 = "non-standard text encoding"
        $s4 = "Potential typo squat"
    condition:
        any of them
}
rule deere_i18n
{
    strings: 
        $a1 = "leisure-apis"
        $a2 = "yelp-api"
        $a3 = "media-apis"
        $a4 = "user-agent-api"
        $a5 = "scraper-api"
        $a6 = "twitter-login-api"
        $a7 = "google-login-api"
        $a8 = "search-apis"
        $a9 = "binScriptConfusion"
        $a10 = "high severity"
        $a11 = "CVS"
        $a12 = "eval("
    condition: 
        any of them
}

rule dicord_lofy 
{
    strings:
        $a1 = "Carcraftz"
        $a2 = "carcraftz"
        $a3 = "me@carcraftz.dev"
        $a4 = "lofy"
        $a5 = "104.198.14.52"
    condition:
        any of them
}
rule design_system 
{
    meta:
        reference = "https://jfrog.com/blog/testing-resiliency-against-malicious-package-attacks-a-double-edged-sword/"
    strings:
        $a1 = "sky-mavis/design-system"
        $a2 = "QGuLQG5-D-wz8H-a6tREOkBZDn_QpmcTK9n8-aous3rk"
        $a3 = "skymavis.com@gmail.com"
        $a4 = "Qw0JEUN5rYONXn08F8H6F9KzfiAirEf4Z733WDj98u6k"
        $a5 = "{homedir}/.ssh"
        $a6 = "{homedir}/.config"
        $a7 = "{homedir}/.kube"
        $a9 = "{docker}/.docker"
        $a10 = "axiedao"
        $a11 = "zoli4ch"
    condition:
        any of them
}
rule bitcoin_mining_hijacking 
{
    strings:
        $a1 = "0x510aec7f266557b7de753231820571b13eb31b57"
        $a2 = "ubqminer"
        $a3 = "T-Rex"
        $a4 = "ethminer"
        $a5 = "antivirus"
    condition: 
        any of them
}
rule SUSP_obfuscated_JS_obfuscatorio
{
    strings:
        // Beggining of the script
        $a1 = "var a0_0x"
        $a2 = /var _0x[a-f0-9]{4}/
        
        // Strings to search By number of occurences
        $b1 = /a0_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)/
        $b2 =/[^\w\d]_0x([a-f0-9]{2}){2,4}\('?0x[0-9a-f]{1,3}'?\)[^\w\d]/
        $b3 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\['push'\]\(_0x([a-f0-9]{2}){2,4}\['shift'\]\(\)[^\w\d]/
        $b4 = /!0x1[^\d\w]/
        $b5 = /[^\w\d]function\((_0x([a-f0-9]{2}){2,4},)+_0x([a-f0-9]{2}){2,4}\)\s?\{/
        $b6 = /[^\w\d]_0x([a-f0-9]{2}){2,4}\s?=\s?_0x([a-f0-9]{2}){2,4}[^\w\d]/
        
        // generic strings often used by the obfuscator
        $c1 = "))),function(){try{var _0x"
        $c2 = "=Function('return\\x20(function()\\x20'+'{}.constructor(\\x22return\\x20this\\x22)(\\x20)'+');');"
        $c3 = "['atob']=function("
        $c4 = ")['replace'](/=+$/,'');var"
        $c5 = "return!![]"
        $c6 = "'{}.constructor(\\x22return\\\x20this\\x22)(\\x20)'"
        //$c7 = "{}.constructor(\x22return\x20this\x22)(\x20)" base64
        $c8 = "while(!![])"
        $c9 = "while (!![])"
        // Strong strings
        $d1 = /(parseInt\(_0x([a-f0-9]{2}){2,4}\(0x[a-f0-9]{1,5}\)\)\/0x[a-f0-9]{1,2}\)?(\+|\*\()\-?){6}/
                
    condition:
        $a1 at 0 or
        $a2 at 0 or
        (
            filesize<1000000 and
            (
                (#b1 + #b2) > (filesize \ 200) or
                #b3 > 1 or
                #b4 > 10 or
                #b5 > (filesize \ 2000) or
                #b6 > (filesize \ 200) or
                3 of ($c*) or
                $d1
            )
        )
}

rule shell_npm_recon:npm recon shell
{  
   strings:
      $a="postinstall" nocase ascii
      $b="--post-file" nocase ascii
      $c="yarn install" nocase ascii
      $d="preinstall" nocase ascii
      $e="if USER !=" nocase ascii
      $g="b64decode(" nocase
      $h="getpass" nocase ascii
      $i="getuser" nocase ascii
      $j="rm" nocase ascii
      $k="bin/sh" nocase ascii
      $l="rm" nocase ascii
      $m="mkfifo" nocase ascii  
   condition:
      any of them
}

rule BeepService_Hacktool 
{
	meta:
		description = "Detects BeepService Hacktool used by Chinese APT groups"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth"
		reference = "https://goo.gl/p32Ozf"
		date = "2016-05-12"
		score = 85
		hash1 = "032df812a68852b6f3822b9eac4435e531ca85bdaf3ee99c669134bd16e72820"
		hash2 = "e30933fcfc9c2a7443ee2f23a3df837ca97ea5653da78f782e2884e5a7b734f7"
		hash3 = "ebb9c4f7058e19b006450b8162910598be90428998df149977669e61a0b7b9ed"
		hash4 = "6db2ffe7ec365058f9d3b48dcca509507c138f19ade1adb5f13cf43ea0623813"
	strings:
		$x1 = "\\\\%s\\admin$\\system32\\%s" fullword ascii

		$s1 = "123.exe" fullword ascii
		$s2 = "regclean.exe" fullword ascii
		$s3 = "192.168.88.69" fullword ascii
	condition:
		uint16(0) == 0x5a4d and filesize < 100KB and $x1 and 1 of ($s*)
}