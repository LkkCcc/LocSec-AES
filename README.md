# LocSec-AES
_Locchan's secure AES encryption_\
_(part of never finished LocSec project)_

A simple library which provides one-function-call strong AES encryption/decryption with data integrity checks.

Requires no dependencies:\
The only dependency is your python being built with openssl or some kind of other crypto lib support\
There is 99.999% chance your python is suitable, and if it isn't, you certainly know it.

Usage is easily understandable by looking at tests. (There's literally two main functions in the whole lib)

### Major versions' encrypted data (w and x in w.x.y.z) may (and will) be not compatible with other major versions.