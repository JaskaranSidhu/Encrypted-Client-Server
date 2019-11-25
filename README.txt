Jaskaran Sidhu

I have 5 files which consists of Client.java, cryptoUtilities.java, Server.java, ServerThread.java and this README.txt file. 

Client.java: This is the code for the client, which is where the encryption takes place. It will then send the encrypted message in a byte array to the server. This is also where part of the key configuration takes place. 

Server.java: Added the debug flag to check if the user would like print statements for all protocols. 

ServerThread.java: This is where all of the decryption happens, once the message is received and decrypted it then sends an acknowledgement message to the client side. This is also where part of the key configuration takes place. 

CryptoUtilities.java: Used for the encryption and decryption. 

To compile and run:

javac Server.java
java Server PORTNUMBER OPTIONALDEBUG

javac Client.java
java Client 0.0.0.0 PORTNUMBER

Where PORTNUMBER is the port number that must match the client side and OPTIONALDEBUG is a optional parameter in which if it is equal to "debug" it will add print statements for all the protocols. 
0.0.0.0 is the parameter for the IP of the server.
 

The server is printing out a acknowledgement when it receives the file name in which it will be storing the message, the length of the encrypted file, the cipher-text in a byte array, and when the message has been correctly/incorrectly decrypted.

Both encryption and data integrity come for from the encryption and decryption methods. After encrypting it will append a message digest and when decrypting it will recompute the digest and check to see if they are the same. This will allow us to see if the message has been tampered with, achieving data integrity and preventing attacks on the integrity of the data. The encryption is (AES-128). The encryption is how I am preventing attacks on confidentiality, as no one can read the encrypted message unless they have the key. The Key is created using the Diffie-Hellman protocol. My implementation of this protocol was implemented by beginning to generate a 512-bit random prime number P with certainty 3. I then check if the prime is a safe prime, and if it is not, I will generate another prime and keep this loop going on until I have generated a safe prime (2q + 1 = p, where q is also a prime). So far everything is done using BigIntegers. I then find the primitive root of p, and save it as an integer. I then send the prime number p, and the primitive root g, to the client over the network insecurely. The client and server will both begin to generate a random number a,b such that 0 <= a, b <= p - 2. I then use those numbers so the client and server can generate g^a (mod p) and g^b (mod p), respectively. They send the computed numbers to each other, and the client and server will then compute (g^b)^a (mod p) and (g^a)^b (mod p), respectively. This will give both parties the same secure seed. Both parties will then apply a hash and get the shared key which can then be used to encrypted and decrypted securely.
