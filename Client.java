// Jaskaran Sidhu
import java.io.*;
import java.net.*;
import javax.crypto.spec.*;
import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.*;


/**
 * Client program.  Connects to the server and sends text accross.
 */

public class Client 
{
    private Socket sock;  //Socket to communicate with.
    public byte[] aes_ciphertext;
    public int read_bytes;
	
    /**
     * Main method, starts the client.
     * @param args args[0] needs to be a hostname, args[1] a port number.
     */
    public static void main (String [] args) throws Exception {
		if (args.length != 2) {
		    System.out.println ("Usage: java Client hostname port#");
		    System.out.println ("hostname is a string identifying your server");
		    System.out.println ("port is a positive integer identifying the port to connect to the server");
		    return;
		}

		try {
		    Client c = new Client (args[0], Integer.parseInt(args[1]));
		}
		catch (NumberFormatException e) {
		    System.out.println ("Usage: java Client hostname port#");
		    System.out.println ("Second argument was not a port number");
		    return;
		}
    }
	
    /**
     * Constructor, in this case does everything.
     * @param ipaddress The hostname to connect to.
     * @param port The port to connect to.
     */
    public Client (String ipaddress, int port){
		/* Allows us to get input from the keyboard. */
		BufferedReader stdIn = new BufferedReader(new InputStreamReader(System.in));
		String userinput;
		String plaintextFileName;
		String encryptedFile;
		byte[] ciphertext = null;
		String seed;
		DataOutputStream out;
		DataInputStream in = null;
		boolean achieved;
		/* Try to connect to the specified host on the specified port. */
		try {
		    sock = new Socket (InetAddress.getByName(ipaddress), port);
		}
		catch (UnknownHostException e) {
		    System.out.println ("Usage: java Client hostname port#");
		    System.out.println ("First argument is not a valid hostname");
		    return;
		}
		catch (IOException e) {
		    System.out.println ("Could not connect to " + ipaddress + ".");
		    return;
		}
		
		/* Status info */
		System.out.println ("Connected to " + sock.getInetAddress().getHostAddress() + " on port " + port);
			
		try {
		    out = new DataOutputStream(sock.getOutputStream());
		    in = new DataInputStream (sock.getInputStream());
		}
		catch (IOException e) {
		    System.out.println ("Could not create output stream.");
		    return;
		}


		try {

//___________________
			int primeByteLength = in.readInt();
			byte[] primeByte = new byte[primeByteLength];
			in.readFully(primeByte);
			BigInteger myPrime = new BigInteger(primeByte);
			int g = in.readInt();

			int b1Length = in.readInt();
			byte[] keyArray = new byte[b1Length];
			in.readFully(keyArray);

			int random = Math.abs((int) (Math.random() * myPrime.intValue()));
			System.out.println("Random number: " + random);

			BigInteger x = (BigInteger.valueOf(g).pow(random)).mod(myPrime);
			System.out.println("X: " + x);

			byte b2[];
			b2 = x.toByteArray();

			out.writeInt(b2.length);
			out.write(b2);

			System.out.println("MY PRIME: " + myPrime);


//___________________


			BigInteger keyNumber = new BigInteger(keyArray);
			keyNumber = keyNumber.modPow(BigInteger.valueOf(random), myPrime);

			seed = keyNumber.toString();

			System.out.println("Key:  " + keyNumber);
			System.out.println("Seed: " + seed);

		} catch (Exception e) {
		    return;
		}




		try {
			/* Wait for the user to type stuff. */
			System.out.println("Please enter the name of the file that you are encrypting.");
			plaintextFileName = stdIn.readLine();
			System.out.println("Please enter the name of the file the decryption will be saved on.");
			encryptedFile = stdIn.readLine();

		} catch (IOException e) {
	    	System.out.println ("Could not read from input.");
	    	return;
		}


		try {
			ciphertext = secureFile(plaintextFileName, encryptedFile, seed);
			out.writeUTF(encryptedFile);
			out.writeInt(read_bytes);
			out.write(aes_ciphertext);
			//out.flush();

			achieved = in.readBoolean();
			if(achieved == true) {
				System.out.println("The message has been succesfully decrypted by the server.");
			} else {
				System.out.println("The message was unsuccesfully decrypted by the server.");
			}
		} catch(Exception e) {
			return;
		}
	}

	byte[] secureFile(String plaintextFileName, String encryptedFile, String seed) throws Exception {
		FileInputStream in_file = null;
		FileOutputStream out_file = null;
		try{
		    // open input and output files
		    in_file = new FileInputStream(plaintextFileName);
		    out_file = new FileOutputStream(encryptedFile);

		    // read input file into a byte array
		    byte[] msg = new byte[in_file.available()];
		    read_bytes = in_file.read(msg);

		    // compute key:  1st 16 bytes of SHA-1 hash of seed
		    SecretKeySpec key = CryptoUtilities.key_from_seed(seed.getBytes());

		    // append HMAC-SHA-1 message digest
		    byte[] hashed_msg = CryptoUtilities.append_hash(msg,key);

		    // do AES encryption
		    aes_ciphertext = CryptoUtilities.encrypt(hashed_msg,key);

		    read_bytes = aes_ciphertext.length;

		    // output the ciphertext
		    out_file.write(aes_ciphertext);
		    out_file.close();
		}
		catch(Exception e){
		    System.out.println(e);
		    return null;
		}
		finally{
		    if (in_file != null){
				in_file.close();
				return null;
		    }
		}
		return aes_ciphertext;
	}
}