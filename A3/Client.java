import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.io.*;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.nio.charset.StandardCharsets;
import java.math.BigInteger;
import java.net.*;
import java.math.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

class Client {
 public static void main( String args[] ) throws Exception {
	// ------------------------------ Socket Programming Set-up --------------------------------- 
	DatagramSocket socket = new DatagramSocket();
    socket.setSoTimeout( 5000 );
	
	// ------------------------------ STS Protocol Set-up --------------------------------------- 
	SecureRandom random = new SecureRandom();
	int BIT_LENGTH = 512;
	
	BigInteger g = BigInteger.probablePrime(BIT_LENGTH / 2, random); // g = large random private prime number
	BigInteger x = new BigInteger("3"); // x = 3
	BigInteger ce = g.pow(x.intValue()); // ce = g^x, (ce = client exponential)
	
	// ------------------------------ RSA with Signature Generation ------------------------------ 
	  // User parameter
	int BIT_LENGTH2 = 2048;
	// Generate random primes
	Random rand = new SecureRandom();
	BigInteger p = BigInteger.probablePrime(BIT_LENGTH2 / 2, rand); // p
	BigInteger q = BigInteger.probablePrime(BIT_LENGTH2 / 2, rand); // q

	// Calculate products
	BigInteger n = p.multiply(q); // n = p x q
	BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // phi = (p-1)x(q-1)

	// Generate public and private exponents
	BigInteger e;
	do e = new BigInteger(phi.bitLength(), new Random());
	while (e.compareTo(BigInteger.ONE) <= 0 || e.compareTo(phi) >= 0 || !e.gcd(phi).equals(BigInteger.ONE)); // gcd(e, phi) = 1
	BigInteger d = e.modInverse(phi); // d = e^-1 mod(phi)
	
	// ---------------------------------- First Message String -------------------------------------
	// Sending to server... g^x, g, e, n
	String message1 = (ce.toString() + " " + g.toString() + " " + e.toString() + " " + n.toString()); // create message string to send
	byte[] buffer = message1.getBytes(); // Converts message into bytes to put in packet
	DatagramPacket packet = new DatagramPacket(buffer,buffer.length,InetAddress.getByName("localhost"),7); // First packet crested
	//System.out.println("Sending message: " + message1);
	socket.send( packet ); // Sends the first message to the server
	
	// Establishing connection speed to test if a connection to the server was achieved
    Date timeSent = new Date();
    socket.receive( packet ); // Waits for response from server
    Date timeReceived = new Date();
    System.out.println("Connection speed: "+(timeReceived.getTime()-timeSent.getTime())+" ms");
    
	// ------------------------------- First Message Received --------------------------------------
	// Received from server... g^y, encrypted message, e1, n1
	byte[] receiveData = new byte[4096]; // need big enough datapacket to receive multiple BigIntegers
	DatagramPacket receivePacket = new DatagramPacket(receiveData,receiveData.length);
	socket.receive( receivePacket ); // Client waits for a reply from server
	String message2 = new String(receivePacket.getData(),0,receivePacket.getLength()); // Converts packet data to message string
	//System.out.println("Message reply received: " + message2);
	String[] words = message2.split(" "); // Separate message into words (variables)
	
	BigInteger se = new BigInteger(words[0]); // g^y
	BigInteger encrypted_signature = new BigInteger(words[1]); // encrypted message
	BigInteger e1 = new BigInteger(words[2]); // e1 = servers public key(1/2)
	BigInteger n1 = new BigInteger(words[3]); // n1 = servers public key(2/2)
	
	BigInteger Session_key = se.pow(x.intValue()); // generate session key k = (g^y)^x
	
	BigInteger signature = encrypted_signature.modPow(d, n); // decrypt with private key to get signature
	BigInteger hashed_message = signature.modPow(e1, n1); // un-sign signature with servers public key to get the hashed message 
	
	//Client creates hashed message to compare to servers one
	String joint = (String.valueOf(se) + String.valueOf(ce)); // g^y || g^x
	BigInteger server_message = new BigInteger(sha256(joint), 16); // h(g^y || g^x)
	
	System.out.println("Validity of the server: " + (server_message.compareTo(hashed_message) == 0)); // returns true if validity of server confirmed (Note: fails occasionally but unsure why)
	
	// ----------------- Create and Send Own Encrypted Signed Hashed Message to Server --------------
	
	// Create own hashed message
	String joint2 = (String.valueOf(ce) + String.valueOf(se)); // g^x || g^y
	BigInteger hashed_message2 = new BigInteger(sha256(joint), 16); // h(g^x || g^y)
	
	BigInteger signature2 = hashed_message2.modPow(d, n); // generate signature
	BigInteger encrypted_signature2 = signature2.modPow(e1, n1); // Encrypt clients signature using the servers public key (e1, n1)
	
	
	// send encrypted message to server
	String message3 = (encrypted_signature2.toString());
	byte[] buffer2 = message3.getBytes(); // Converts message into bytes to put in packet
	DatagramPacket packet2 = new DatagramPacket(buffer2,buffer2.length,InetAddress.getByName("localhost"),7); // First packet crested
	//System.out.println("Sending message: " + message1);
	socket.send( packet2 ); // Sends the first message to the server
	Date timeSent2 = new Date();
    socket.receive( packet2 ); // Waits for response from server
    Date timeReceived2 = new Date();
    System.out.println("Connection speed: "+(timeReceived2.getTime()-timeSent2.getTime())+" ms");
	
	// ------------------------------- Triple DES with CTR Mode ----------------------------------
	
	DESCipher encrypter = new DESCipher(Session_key); // create new DES Cipher object initialized with the session key
	byte[] cyphertext = encrypter.encrypt("This test message64b from the client is being sent to the server"); // encrypt plaintext message using DES with CTR
	
	byte[] nonce = encrypter.returnNonce(); // get nonce to send to server
	
	// Create message packet in bytes because converting bytes to string then back to bytes will cause data loss
	byte[] message_packet = new byte[nonce.length + cyphertext.length]; // concatenate nonce with cyphertext 
	System.arraycopy(nonce, 0, message_packet, 0, nonce.length);
	System.arraycopy(cyphertext, 0, message_packet, nonce.length, cyphertext.length);
	
	// send to server
	DatagramPacket packet3 = new DatagramPacket(message_packet,message_packet.length,InetAddress.getByName("localhost"),7); // First packet crested
	//System.out.println("Sending message: " + message1);
	socket.send( packet3 ); // Sends the first message to the server
	Date timeSent3 = new Date();
    socket.receive( packet3 ); // Waits for response from server
    Date timeReceived3 = new Date();
    System.out.println("Connection speed: "+(timeReceived3.getTime()-timeSent3.getTime())+" ms");
	
	// ---------------------------------------------------------------------------------------------
	
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