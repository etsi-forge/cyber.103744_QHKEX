## TS 103 744 Quantum-safe Hybrid Key Exchanges ##

 Informative reference implementation as reported in Annex C of ETSI TS 103 744,
 "CYBER; Quantum-safe Hybrid Key Exchanges. The code is not intended for production use.
 It is intended to be a reference implementation for test.
 
 More information and standards download at the [work item page](https://portal.etsi.org/webapp/WorkProgram/Report_WorkItem.asp?WKI_ID=56659). 
 
 ### Usage ###
 
 This code is provided as an informative implementation of the Quantum-safe Hybrid Key Exchanges for the Concatenate 
 KDF (CatKDF) and Cascade KDF (CasKDF).  It generates the test vectors contained in the TS.
 
 This is not intended for production use.  It is intended to be a reference
 implementation for test vectors for the specification.
  
 ### Build instructions ###
 
This library requires OpenSSL version 1.1.1d libcrypto.
 
     gcc -Wall -o etsi-hkex-test main.c qshkex.c -lcrypto
     ./etsi-hkex-test
     
### License ###     
The content of this repository and the files
contained are released under the BSD-3-Clause license.
See the attached LICENSE file or visit https://forge.etsi.org/legal-matters.