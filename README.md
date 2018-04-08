# sm-crypto
National Encryption Algorithm refers to the domestic commercial cipher algorithm of Office of Security Commercial Code Administration of China. In the applications of financial part, people mainly use three kinds of public encryption algorithms including SM2, SM3, SM4. They are asymmetric algorithm, the hash algorithm and the symmetric algorithm respectively.

The goal of every encryption algorithm is to make it as difficult as possible to decrypt the generated ciphertext without using the key. If a really good encryption algorithm is used, there is no technique significantly better than methodically trying every possible key. For such an algorithm, the longer the key, the more difficult it is to decrypt a piece of ciphertext without possessing the key.

Here are some brief introduction about those algorithms. The ultimate goal of this project is to implement these algorithms and make it possible in practical scenarios. They can be widely used in all kinds of security applications especially in financial services.

The basic process of this project is encryption and decryption. We translate text data using the algorithm into ciphertext and is also able to get the plaintext by decrypting the ciphertext.

SM2 algorithm:
SM2 elliptic curve public key cryptography algorithm is designed as public key cryptographic algorithms, including SM2-1 elliptic curve digital signature algorithm, SM2-2 elliptic curve key exchange protocol and SM2-3 elliptic curve public key encryption algorithm, respectively. They are used to implement a digital signature key agreement and data encryption, and other functions.  The difference between the SM2 algorithm and the RSA algorithm is that the SM2 algorithm is based on the discrete logarithm problem of the point group on the elliptic curve. Compared with the RSA algorithm, the 256-bit SM2 cipher strength is already higher than the 2048-bit RSA cipher strength.

SM3 algorithm: 
The SM3 hash algorithm is suitable for the generation and verification of digital signatures and verification message authentication codes in commercial cryptographic applications and the generation of random numbers, which can meet the security requirements of various cryptographic applications.  In order to ensure the security of the hash algorithm, the length of the hash value generated by it should not be too short. For example, MD5 outputs a 128-bit hash value, and the output length is too short and this affects its security. The output length of the SHA-1 algorithm is 160 bits, and the SM3 algorithm output length is 256 bits. So the security of the SM3 algorithm is higher than that of the MD5 algorithm and the SHA-1 algorithm.


SM4 algorithm: 
SM4 block cipher algorithm is a group symmetric cipher algorithm to realize the encryption/decryption operation of data to ensure the confidentiality of data and information. 
The basic requirement for a symmetric cipher algorithm to guarantee the safety is the enough key length SM4 algorithm and AES algorithm with the same key length packet length is 128 bits, and so on security is higher than 3 des algorithm. The SM4 algorithm and the AES algorithm have the same key-length packet length of 128 bits, and therefore are higher in security than the 3DES algorithm.

# Develop Language
JDK - 1.8

# Reference
http://www.oscca.gov.cn/News/201012/News_1197.htm

# Dependency
bcprov-jdk15 150
