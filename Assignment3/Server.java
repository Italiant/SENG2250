import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.net.*;
import java.math.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

class Server {
  public static void main( String args[] ) throws Exception {
	// ------------------------------ Socket Programming Set-up --------------------------------- 
    DatagramSocket socket = new DatagramSocket(7);
    byte[] receiveData = new byte[4096];
	DatagramPacket packet = new DatagramPacket(receiveData,receiveData.length);
	
    while ( true ) { // keeps server running forever
	System.out.println("");
	// ------------------------------- First Message Received --------------------------------------
      socket.receive( packet ); // Server does not run until a packet is received
	  String message1 = new String(packet.getData(),0,packet.getLength()); // Convert received message into a string
      System.out.println( ""+new Date()+" "+packet.getAddress()+":"+packet.getPort()); // Print connection details
	  //System.out.println("Client received message: " + message1);
	  String[] words = message1.split(" "); // Separates message string into words so can use words array and separate variables
	  socket.send( packet ); // Send back first empty packet to establish a connection speed and to get ip address of sender
	  
	  BigInteger ce = new BigInteger(words[0]); // g^x
	  BigInteger g = new BigInteger(words[1]); // g
	  // Public key pair from client
	  BigInteger e = new BigInteger(words[2]); // e = clients public key(1/2)
	  BigInteger n = new BigInteger(words[3]); // n = clients public key(2/2)
	  
	  BigInteger y = new BigInteger("2"); // y 
	  BigInteger se = g.pow(y.intValue()); // g^y
	  
	  BigInteger Session_key = ce.pow(y.intValue()); // generate session key k = (g^x)^y
	  
	  String joint = (String.valueOf(se) + words[0]); // concatenate into message 
	  BigInteger message = new BigInteger(sha256(joint), 16); // hash message, need to add 16 so BigInteger knows the input as a hex value
	  
	  // ------------------------------ RSA with Signature Generation (Servers Key Pair)------------------------------ 
	  // User parameter
	int BIT_LENGTH = 2048;
	// Generate random primes
	Random rand = new SecureRandom();
	BigInteger p1 = BigInteger.probablePrime(BIT_LENGTH / 2, rand); // p1
	BigInteger q1 = BigInteger.probablePrime(BIT_LENGTH / 2, rand); // q1

	// Calculate products
	BigInteger n1 = p1.multiply(q1); // n1 = p1 x q1
	BigInteger phi = p1.subtract(BigInteger.ONE).multiply(q1.subtract(BigInteger.ONE)); // phi = (p1-1)x(q1-1)

	// Generate public and private exponents
	BigInteger e1;
	do e1 = new BigInteger(phi.bitLength(), new Random());
	while (e1.compareTo(BigInteger.ONE) <= 0 || e1.compareTo(phi) >= 0 || !e1.gcd(phi).equals(BigInteger.ONE));// gcd(e1, phi) = 1
	BigInteger d1 = e1.modInverse(phi); // d1 = e1^-1 mod(phi)
	
	// ---------------------------------- First Message String To Send -------------------------------------
	 
	 BigInteger signature = message.modPow(d1, n1); // Signed message using the servers private key (d1, n1)
	 BigInteger encrypted_signature = signature.modPow(e, n); // encrypted using the clients shared public key (e, n)
	  
	  InetAddress IPAddress = packet.getAddress(); // Get IP address of connection to send back on that same IP
	  int IPPort = packet.getPort();
	  String message2 = se.toString() + " " + encrypted_signature.toString() + " " + e1.toString() + " " + n1.toString();
	  byte[] buffer = message2.getBytes(); // Created message in bytes to send to client
	  DatagramPacket sendPacket = new DatagramPacket(buffer, buffer.length, IPAddress, IPPort); // Created packet to send to client
	  //System.out.println("Sending message: " + message2);
	  socket.send( sendPacket ); // Send first real message/packet to client

	  // ------------------------------- Second Message Received --------------------------------------
	  
	  byte[] receiveData2 = new byte[4096];
	  DatagramPacket packet2 = new DatagramPacket(receiveData2,receiveData2.length);
	  
	  socket.receive( packet2 );
	  String message3 = new String(packet2.getData(),0,packet2.getLength()); // Convert received message into a string
      System.out.println( ""+new Date()+" "+packet2.getAddress()+":"+packet2.getPort()); // Print connection details
	  //System.out.println("Client received message: " + message1);
	  String[] words2 = message3.split(" "); // Separates message string into words so can use words array and separate variables
	  socket.send( packet2 ); // Send back packet to establish a connection speed and to get ip address of sender
	  
	  BigInteger encrypted_signature2 = new BigInteger(words2[0]); // encrypted message
	  
	  BigInteger signature2 = encrypted_signature2.modPow(d1, n1); // decrypt with private key to get signature
	  
	  BigInteger msg2 = signature2.modPow(e, n); // un-sign signature with clients public key to get the hashed message 

	  String joint2 = (String.valueOf(ce) + String.valueOf(se)); // g^x || g^y
	  BigInteger client_message = new BigInteger(sha256(joint), 16); // h(g^x || g^y)
	  
	  System.out.println("Validity of the client: " + (client_message.compareTo(msg2) == 0)); // returns true if validity of client confirmed (Note: fails occasionally but unsure why)
	  
	  // ------------------------------- Triple DES with CTR Mode ----------------------------------
	  
	  byte[] receiveData3 = new byte[4096];
	  DatagramPacket packet3 = new DatagramPacket(receiveData3,receiveData3.length);
	  socket.receive( packet3 ); // receive nonce and cyphertext from client concatenated into a single byte array
	  int length = packet3.getLength();
	  
	  byte[] nonce = new byte[4]; // knowing the nonce is only 4 bytes, make it equal to the first 4 bytes of the array
	  for(int i = 0; i < 4; i++)
		  nonce[i] = packet3.getData()[i];
	  
	  byte[] cyphertext = new byte[length-4]; // make the rest of the array equal to the cyphertext
	  for(int i = 4; i < length; i++)
		  cyphertext[i-4] = packet3.getData()[i];
	  
      System.out.println( ""+new Date()+" "+packet3.getAddress()+":"+packet3.getPort()); // Print connection details
	  socket.send( packet3 ); // Send back packet to establish a connection speed and to get ip address of sender
	  
	  //System.out.println(Arrays.toString(nonce)); // to print a byte array
	  //System.out.println(Arrays.toString(cyphertext));
	  
	  DESCipher decrypter = new DESCipher(Session_key, nonce); // create new DES Cipher object initialized with the session key and nonce
	  byte[] decrypted = decrypter.decrypt(cyphertext); // decrypt the cyphertext
	  System.out.println("Decrypted Client Message: " + new String(decrypted)); // print message which should be the same as the clients therefore confirming DES with CTR
	} // end of while loop
  }
 // SHA-256 Hashing Function
public static String sha256(String plaintext) {
    try{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] hash = digest.digest(plaintext.getBytes("UTF-8"));
        StringBuffer hexString = new StringBuffer();

        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();
		} catch(Exception ex){
			throw new RuntimeException(ex);
			}
	}
}