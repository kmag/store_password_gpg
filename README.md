# store_password_gpg
A simple password generation script that uses GnuPG to store each password in a separate gpg-encrypted file.

## Motivation
The chief reason to store passwords this way is that corruption of a single file loses at most a single password,
and existing passwords can be retrieved anywhere GnuPG runs.  Also, more than a decade ago, the author
wasn't aware of any good cross-platform password managers that could be trusted to not corrupt existing passwords
if power was lost in the middle of generating new passwords.

## Requirements
store_password_gpg.py requires Python 3 and GnuPG to be installed and in the user's PATH.  The user must have at least
one public/private keypair in their GnuPG keyring.

## Limitations on functionality
The easiest way to view an existing password is to attempt to generate a new password for the same domain.
If you attempt to generate a password for a domain where you already have a password, you will be shown a short
warning, followed by being prompted for your GnuPG keyring password and being shown your existing password.  The
existing password file will not be modified.

If you want multiple accounts per domain, you'll have to generate new entries as if they're for dummy accounts
and then manually use gpg -d and ggp -e to merge the files.  This is an uncommon use case for the author,
and supporting it would introduce the possibility of a programming bug causing the loss of an existing password.

## Basic usage
Show command-line help and exit.
> store_password_gpg.py -h

Generate a random password for example.com, using your default email address as the username,
encrypted using the public key for your default email address.
Password is stored in ~/Documents/Passwords/example.com.gpg  (My Documents/Passwords/example.com.gpg on Windows)
> store_password_gpg.py example.com

Generate a random password for example.com, username example, associated email address e2@example.com, and encrypted
using the public keys for both e2@example.com and example@gmail.com
> store_password_gpg.py --user example --email e2@example.com --key e2@exapmle.com --key example@gmail.com example.com

Keep generating random passwords for example.com until the user sends a keyboard interrupt (ctrl-c on Linux, OS X,
and the Windows cmd.exe shell) to select the last seen password.
> store_password_gpg.py --loop example.com

Keep generating random passwords until stopped via keyboard interrupt.  Don't store anything anywhere.
Choose from only the 62-character alphabet consisting of English letters and digits.  Generate passwords with
approximately 80 bits of entropy.
> store_password_gpg.py --alphabet 62 --bits 80 --loop ""

## Pass phrases instead of passwords
If a file named wordlist.txt.bz2, containing UTF-8 encoded words, one per line, in placed in the password directory,
it can optionally be used to generate pass phrases by passing --alphabet 100 on the commandline.  (Actually, anything over 99
will filter available alphabets/dictionalies to anythig having at least that many entries.)  An alternative location/name
for the wordlist file can be given with the --wordlist commandline flag.  If the --loop option is used and a wordlist is
found, the worldlist will be included in the rotatation of alphabets used to generate candidate passwords/pass phrases.

## Configuration
Configuration is stored in ~/Documents/Passwords/config.json (My Documents/Passwords/config.json on Windows).
Most commandline options are supported as keys for the JSON object literal (minus their leading dashes).
Note that in config.json, non-absolute paths for wordlist are relative to the password directory, not the current
working directory.

> {
> "email" : "e2@example.com",
> "user" : "MyFavHandle",
> "keys" : [ "e2@example.com", "example@email.com" ],
> "bits" : 128,
> "wordlist" : "klingon_swahilli_french.txt.bz2"
> }
