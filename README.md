Project Goal
To demonstrate the vulnerability in a non-standard RSA implementation where the two prime numbers (p and q) are extremely close to each other. The task was to decrypt a ciphertext using only the public key and encrypted message — based on the TryHackMe CryptoSystem challenge.

Description
In a secure RSA implementation, two random and distant prime numbers p and q are selected so that factoring n = p * q becomes practically impossible.

However, in this challenge, q = next_prime(p), meaning the two primes are very close. This introduces a critical weakness. We exploited this flaw by:

Brute-forcing p around sqrt(n);

Reconstructing q = nextprime(p);

Calculating phi(n) = (p-1)(q-1);

Deriving the private key d;

Decrypting the ciphertext to recover the flag.

Full Script
python

from Crypto.Util.number import *
from sympy import isprime, nextprime
import math

# Ciphertext, modulus n, and public exponent e
c = 3591116664311986976882299385598135447435246460706500887241769555088416359682787844532414943573794993699976035504884662834956846849863199643104254423886040489307177240200877443325036469020737734735252009890203860703565467027494906178455257487560902599823364571072627673274663460167258994444999732164163413069705603918912918029341906731249618390560631294516460072060282096338188363218018310558256333502075481132593474784272529318141983016684762611853350058135420177436511646593703541994904632405891675848987355444490338162636360806437862679321612136147437578799696630631933277767263530526354532898655937702383789647510

n = 15956250162063169819282947443743274370048643274416742655348817823973383829364700573954709256391245826513107784713930378963551647706777479778285473302665664446406061485616884195924631582130633137574953293367927991283669562895956699807156958071540818023122362163066253240925121801013767660074748021238790391454429710804497432783852601549399523002968004989537717283440868312648042676103745061431799927120153523260328285953425136675794192604406865878795209326998767174918642599709728617452705492122243853548109914399185369813289827342294084203933615645390728890698153490318636544474714700796569746488209438597446475170891

e = 0x10001

# Attempt to factor n by brute-forcing primes near sqrt(n)
def factor_n(n):
    approx_p = int(math.isqrt(n))
    if approx_p % 2 == 0:
        approx_p -= 1
    for i in range(10000):
        p = approx_p - i
        if isprime(p):
            q = nextprime(p)
            if p * q == n:
                return p, q
    return None, None

# Retrieve p and q
p, q = factor_n(n)
if p is None:
    print("[-] Failed to factor n")
    exit()

# Compute the private key
phi = (p - 1) * (q - 1)
d = inverse(e, phi)

# Decrypt the ciphertext
m = pow(c, d, n)
plaintext = long_to_bytes(m)
print(f"[+] FLAG: {plaintext.decode()}")
Technologies Used
Language: Python 3

Libraries: pycryptodome, sympy

Platform: Linux (TryHackMe virtual machine)

Technique: Brute-forcing p near sqrt(n) due to non-standard RSA prime generation

Output
Upon execution, the script outputs the following:

css

[+] FLAG: THM{Just_sm3_small_amount_of_RSA!}
📌 Key Takeaways
Even small deviations from RSA best practices (like using q = next_prime(p)) can fully compromise the encryption.

Understanding RSA’s theoretical foundation is essential — but implementation details matter even more.

Cryptanalysis often doesn’t require attacking the cipher itself, but rather its weak setup.
