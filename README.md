**What is DES?** 

It is an encryption/decryption algrotihm or technique used to encrypt and decrypt a block of data. You can read more about the algorithm [here](http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm) and also [here](http://www.umsl.edu/~siegelj/information_theory/projects/des.netau.net/Dataencryptionalgorithm.html).


**Features of DES:**

1. It used to encrypt messgae (plain text) of length 64-bits and produce the cipher text (unreadable message) of length 64-bit too.<br>
2. It used symmetric key, means that the same key will be used for both encryption & decryption. <br>
3. It gets the power from using the F function which is a function involves several consecutive steps.<br>
4. The algorithm involves 16-rounds and in each round there is 48-bit key(i) used for both encryption & decryption. 


 **Message Processing**
 
 Some of code snippet from our project. Here we're trying to convert our initial plain text (message) to binary:
       
        initialMsg = plainText.get(1.0,END)
        if len(initialMsg) < 9 or len(initialMsg) > 9:
            print("Please, enter 64 bits or 8 bytes as initial message ")
        else:
            byteMsg = initialMsg.encode('utf-8')
            hexaMsg = str(byteMsg.hex())
            tempMsg = []
            s = ""
            for i in str(hexaMsg):
                for j in hexa_to_bin:
                    if i == j:
                        tempMsg.append(hexa_to_bin[j])
            binMsg = s.join(tempMsg)
## What is 3DES?

3DES (Triple DES) is an enhanced encryption algorithm based on the DES standard. It applies the DES algorithm three times to each data block to increase security.

### How 3DES Works:
1. Encrypt the plaintext with **Key 1**.
2. Decrypt the result with **Key 2**.
3. Encrypt again with **Key 3**.

### Features of 3DES:
- Uses **three keys** (Key 1, Key 2, Key 3), each of 64 bits.
- Strengthens DES by performing multiple encryption steps.
- Suitable for encrypting and decrypting sensitive data.

### Message Processing in 3DES:
Example code snippet for encryption:
```python
cipher1 = DES_encrypt(message, key1)
cipher2 = DES_decrypt(cipher1, key2)
final_cipher = DES_encrypt(cipher2, key3)
#   E n c r y p t D e c r y p t - 3 D E S  
 