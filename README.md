# PA2 - Hashing and Passwords: Due 10/25 at 10pm

[Cryptographic hash functions](https://en.wikipedia.org/wiki/Cryptographic_hash_function) take an input of arbitrary length and produces a fixed length output. The special features are that the outputs are *deterministic* (the same input always generates the same output) and yet the outputs are apparently “random” – two similar inputs are likely to produce very different outputs, and it's difficult to determine the input by looking at the ouput.

A common application of hashing is in storing passwords. Many systems store only the hash of a user's password along with their username. This ensures that even if someone gains access to the stored data, users' actual passwords are not exposed. When a user types in a password on such a system, the password handling software grants access if the hash value generated from the user's entry matches the hash stored in the password database.

We said above that it is *difficult* to determine an input given an output. [Password cracking](https://en.wikipedia.org/wiki/Password_cracking) is a family of techniques for accomplishing this difficult (but possible!) task.
That is, let's say we have access to a user's password *hash* only. Can we figure out their password? We could then use it to log in, and it may also be shared across their accounts which we could also access.

In some cases, password cracking can [exploit the structure](https://en.wikipedia.org/wiki/MD5#Security) of a hash function; this is a topic for a cryptography class. In our case, we will take a more brute-force approach: trying variations on existing known passwords, under the assumption that [many passwords are easy to guess](https://en.wikipedia.org/wiki/List_of_the_most_common_passwords).

## Getting Started
To get started, visit the [Github Classroom](https://classroom.github.com/a/Lo9vRhLG) assignment link. Select your username from the list (or if you don't see it, you can skip and use your Github username). A repository will be created for you to use for your work. This PA should be completed on the `ieng6` server. Refer [this](https://ucsd-cse29.github.io/fa24/week1/index.html#logging-into-ieng6) section in Week 1's Lab for instructions on logging in to your account on `ieng6` and working with files on the server.

## Overall Task

We'll start by describing the overall task and goal so it's clear where you're going.
However, don't start by trying to implement this exactly – use the milestones below to get there.

### `pwcrack`, a Password Cracker

Write a program `pwcrack` that takes one command-line argument, the `SHA256` hash of a password in hex format.

The program then reads from `stdin` potential passwords, one per line (assumed to be in UTF-8 format).

The program should, for each password:

- Check if the SHA256 hash of the potential password matches the given hash
- Check if the SHA256 hash of the potential password with each of its ASCII characters
  uppercased or lowercased matches the given hash

If a matching password is found, the program should print

```
Found password: SHA256(<matching password>) = <hash>
```

If a matching password is *not* found, the program should print:

```
Did not find a matching password
```

### Examples

`seCret` has a SHA256 hash of `a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd`, and `notinlist`
has a SHA256 hash of `21d3162352fdd45e05d052398c1ddb2ca5e9fc0a13e534f3c183f9f5b2f4a041`

```
$ ./pwcrack a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd
Password
NeverGuessMe!!
secret
Found password: SHA256(seCret) = a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd
$ ./pwcrack 21d3162352fdd45e05d052398c1ddb2ca5e9fc0a13e534f3c183f9f5b2f4a041
Password
NeverGuessMe!!
secret
<Press Ctrl-D for end of input>
Did not find a matching password
```

We could also put the potential passwords in a file:

```
$ cat guesses.txt
Password
NeverGuessMe!!
secret
$ ./pwcrack a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd < guesses.txt
Found password: SHA256(seCret) = a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd
```

Note that we only consider single-character changes when trying 
uppercase/lowercase variants of the guesses (i.e. we DON'T try all possible 
capitalizations of the string): In the example below, the correct password is 
NOT found because going from `SECRET` to `seCret` would require 4 characters to be changed.

```
$ ./pwcrack a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd
SECRET
<Press Ctrl-D for end of input>
Did not find a matching password
```

To help testing your PA, we are providing you with a file containing 3 million real paintext passwords famously found a data breach of the [RockYou
social network](https://en.wikipedia.org/wiki/RockYou) in 2009. You can use the password file present in the `ieng6` servers by reading it into `pwcrack` using
the following commandline.
```
$./pwcrack < /home/linux/ieng6/cs29fa24/pa2/rockyou_clean.txt
```

Note: these are real human-generated passwords, so they may contain profane words (and offensive concepts). We are providing a
censored version of the RockYou password list. Our filtering methodology was to remove any passwords that matched a widely-used 2,800 profane
word list. If you read the conents of the password file, note that you are doing so at your own risk, as we can not guarantee that we removed
all offensive passwords from the list.

## Useful Tools

You will be using [`openssl`](https://docs.openssl.org/3.1/man3/SHA256_Init) library for this PA. This requires an extra argument for compiling your code:
```
gcc <your .c file> -o <output name> -lcrypto
```

The relevant function from that library is `SHA256`. You can follow the link above to see its official type; in terms we've been using in class its type is:

```
SHA256(const unsigned char data[], uint64_t count, unsigned char md_buf[]);
```

The `data` parameter is *not* assumed to be a C string. That is, it may or may not be null terminated, `SHA256` won't check. The hash function will operate on however many bytes are specified by `count`. So, if passing a C string, the caller of `SHA256` is responsible for using something like `strlen` to calculate `count` and provide it.
The `md_buf` argument is where the hash gets stored, and it is assumed to be at least 32 bytes long (SHA256 has a fixed output size which is 32 bytes (256 bits)).


Here's a short code snippet that shows how to use it:

```
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <openssl/sha.h>

const int SHA_LENGTH = 32;

int main(int argc, char** argv) {
    uint8_t i = 0;
    // SHA256 hashes are always 32 bytes long (independent of input length)
    unsigned char hash[SHA_LENGTH];
    // argv[1] is the first command-line argument as a C string
    SHA256(argv[1], strlen(argv[1]), hash); // result stored in hash
    for(i = 0; i < SHA_LENGTH; i += 1) {
        printf("%02x", hash[i]); // %02x means print as a 2-digit hex value
    }
    printf("\n");
    for(i = 0; i < SHA_LENGTH; i += 1) {
        printf("%d ", hash[i]);
    }
    printf("\n");
}
```

Example:

```
[cs29fa24@ieng6-201]:~:201$ gcc sha256.c -o sha256 -lcrypto
[cs29fa24@ieng6-201]:~:204$ ./sha256 seCret
a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd
162 195 176 44 178 42 248 61 109 30 173 29 78 24 217 22 89 155 231 194 239 47 1 113 105 50 125 241 247 200 68 253 
```

If you want to calculate a sha256 hash yourself you can use that program, there's also a command-line program called `openssl` that can do this from standard input:

```
[cs29fa24@ieng6-201]:~:203$ echo -n seCret | openssl dgst -sha256
(stdin)= a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd
``` 

This also generates a SHA256 hash string of `seCret`. Note that both examples show 64 characters of hex values. 2 hex characters are used to represent one byte, so 64 hex characters are used to represent 32 bytes. (The `-n` argument to `echo` means “don't add a newline.” Without this, we'd get the hash of `seCret\n`)


## Milestones and Incremental Testing

We provide some milestones for you to work incrementally. We also describe some testing strategies here that might help you do your work one function at a time.

### Functions - Milestone 1

The first milestone has you work on handling user input, which is given as a 64-byte ASCII string of hex characters. In order to compare this to hash values, it will be useful to convert this to the numeric bytes representing the hash value.

#### `hex_to_byte`


```
uint8_t hex_to_byte(unsigned char h1, unsigned char h2);
```

Given two hex characters in ASCII (0-9, a-f) representing a two-digit hexadecimal number, return the integer they represent. `h1` is the most significant digit, `h2` the least.


```
assert(hex_to_byte('c', '8') == 201);
assert(hex_to_byte('0', '3') == 3);
assert(hex_to_byte('0', 'a') == 10);
assert(hex_to_byte('1', '0') == 16);
```

#### `hexstr_to_hash`

```
void hexstr_to_hash(unsigned char hexstr[], char hash[32])
```

Given 64 hex characters in ASCII (e.g. user input), convert it to a 32-byte array corresponding to the hex values. Assume the first 64 bytes (exactly) of hex contain the input data.

```
char hexstr[64] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
char hash[32];
hexstr_to_hash(hexstr, hash);
// hash should now contain { 0xa2, 0xc3, 0xb0, 0x2c, ... }
```


#### `main` for Milestone 1

At this point, you aren't yet reading any input from stdin, but you can verify that you can read the command-line argument. It could be useful at this point to check your work by printing a message that verifies you correctly read the input.

For example:

```
int main(int argc, char** argv) {
  char hash[32];
  hexstr_to_hash(argv[1], hash);
  printf("User input as hash: \n");
  // print out hash (you can use our main method from the SHA256 example
}
```

#### Testing Milestone 1

There are a few ways to test Milestone 1. One is with `assert`s as shown above (note: you will need to `#include <assert.h>`). Another is to print out some information and verify it. For example, you might find it useful to `printf` the contents of the result of `hexstr_to_hash`.

A way to organize this in your code could be to write individual test functions, and call them conditionally at the top of the `main` function:

```
#include <assert.h>

void test_hex_to_byte() {
  assert(hex_to_byte('c', '8') == 201)
  ...
}
void test_hexstr_to_hash() {
  char hexstr[64] = "a2c3b02cb22af83d6d1ead1d4e18d916599be7c2ef2f017169327df1f7c844fd";
  char hash[32];
  hexstr_to_hash(hexstr, hash);
  for(int i = 0; i < 32; i += 1) { ... print something about hash ... }
  assert(hash[0] == 0xa2);
  assert(hash[31] == 0xfd);
}
const int testing = 1;
int main(int argc, char** argv) {
  if(testing) {
    test_hex_to_byte();
    test_hexstr_to_hash();
  }
  char hash[32];
  hexstr_to_hash(argv[1], hash);
  // ... other work in main ...
}
```


### Functions - Milestone 2


#### `check_password`

Given a password as a C string and a SHA256 hash as an array of bytes, check the hash of the password against the `given_hash`. Return `1` if they match, `0` if not.


```
int8_t check_password(char password[], char given_hash[32])

// Example:
// char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; // SHA256 hash for "password"
// char given_hash[32];
// hexstr_to_hash(hash_as_hexstr, given_hash);
// assert(check_password("password", given_hash) == 1);
// assert(check_password("wrongpass", given_hash) == 0);
```


#### `main` Function Milestone 2

With `check_password`, you can now check for exact matches of passwords given on `stdin` with the hash the user gave. You should be able to get this test working:

```
$ ./pwcrack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
notpassword
password
Found password: SHA256(password) = 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
```

However, this doesn't yet atttempt capitalization variation, so if `Password` but not `password` is given, there won't be a match:

```
$ ./pwcrack 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
notpassword
Password
<Press Ctrl-D for end of input>
Did not find a matching password
```

#### Testing Milestone 2

For testing milestone 2, using `assert`s in a test function (as suggested in Milestone 1) is a good way to ensure you are correctly matching passwords to their hashes.


### Functions - Milestone 3

#### `crack_password`

```
int8_t crack_password(char password[], char given_hash[])
```

Given a password string and hash, attempt to match the given password and all variations of the given password made by uppercasing or lowercasing a single ASCII character.

Returns `1` on match and `0` if no match. In addition, if `1` is returned, the `password` string should reflect the variation that matched (e.g. if it required uppercasing a character, that update should be visible in `password`).

```
// char password[] = "paSsword";
// char hash_as_hexstr[] = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"; // SHA256 hash of "password"
// char given_hash[32];
// hexstr_to_hash(hash_as_hexstr, given_hash);
// int8_t match = crack_password(password, given_hash);
// assert(match == 1);
// assert(password[2] == 's'); // the uppercase 'S' has been lowercased
```

With this function, you should be able to complete the original task.


## Design Question

Real password crackers try many more variations than just uppercasing and lowercasing. Do a little research on password cracking and suggest at least 2 other ways to vary a password to crack it. Describe them both, and for each, write a sentence or two about what modifications you would make to your code to implement them.

## Handin

- Any .c files you wrote (can be one file or many; it's totally reasonable to only have one). We will run `gcc *.c -o pwcrack -lcrypto` to compile your code, so you should make sure it works when we do that.
- A file DESIGN.md (with exactly that name) containing the answers to the design questions

You will hand in your code to the `pa2` assignment on Gradescope. An autograder will give you information about if your code compiles and works on some simple examples like the ones from this writeup. Your implementation and design questions will be graded after the deadline with a mix of automatic and manual grading.
