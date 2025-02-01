/*
   YARA Rule Set
   Author: yarGen Rule Generator
   Date: 2025-02-01
   Identifier: miner
   Reference: https://github.com/Neo23x0/yarGen
*/

/* Rule Set ----------------------------------------------------------------- */

rule minerbuilder {
   meta:
      description = "miner - file minerbuilder.exe"
      author = "yarGen Rule Generator"
      reference = "https://github.com/Neo23x0/yarGen"
      date = "2025-02-01"
      hash1 = "fc21bba6794d69cdbf9d01c3ec7666b1501dd1303efb4200f235662263bbc218"
   strings:
      $s1 = "-225%\\- -<D" fullword ascii /* hex encoded string '"]' */
      $s2 = "http://www.digicert.com/CPS0" fullword ascii
      $s3 = "5http://cacerts.digicert.com/DigiCertTrustedRootG4.crt0C" fullword ascii
      $s4 = "4http://crl3.digicert.com/DigiCertAssuredIDRootCA.crl0" fullword ascii
      $s5 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0" fullword ascii
      $s6 = "7http://cacerts.digicert.com/DigiCertAssuredIDRootCA.crt0E" fullword ascii
      $s7 = "2http://crl3.digicert.com/DigiCertTrustedRootG4.crl0 " fullword ascii
      $s8 = "http://ocsp.digicert.com0\\" fullword ascii
      $s9 = "http://ocsp.digicert.com0X" fullword ascii
      $s10 = "Lhttp://cacerts.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crt0" fullword ascii
      $s11 = "# - &V4" fullword ascii
      $s12 = "  VirtualQuery failed for %d bytes at address %p" fullword ascii
      $s13 = "Mhttp://crl3.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0S" fullword ascii
      $s14 = "Mhttp://crl4.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crl0" fullword ascii
      $s15 = "Ihttp://crl3.digicert.com/DigiCertTrustedG4RSA4096SHA256TimeStampingCA.crl0" fullword ascii
      $s16 = "3(74$>?(%2 -?" fullword ascii /* hex encoded string '7B' */
      $s17 = "6<04F=[!." fullword ascii /* hex encoded string '`O' */
      $s18 = "- +,3*.$4" fullword ascii /* hex encoded string '4' */
      $s19 = "?.);7C+ ?" fullword ascii /* hex encoded string '|' */
      $s20 = "Phttp://cacerts.digicert.com/DigiCertTrustedG4CodeSigningRSA4096SHA3842021CA1.crt0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 9000KB and
      8 of them
}
