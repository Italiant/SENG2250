import java.util.*;
import java.security.*;
import javax.crypto.*;
import java.math.BigInteger;
import java.io.*;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;
public class DESCipher{
	 
  private Cipher ecipher1, ecipher2, ecipher3;
  private SecretKey key1, key2, key3;
  private IvParameterSpec ivs1, ivs2, ivs3;
  private byte[] nonce;

 public DESCipher(BigInteger Session_key) throws Exception { // Constructor for client
	String keyString = Session_key.toString();
	// Separate session key into 3 separate keys of 8 bytes each to combine to make a 24 byte block for CTR and DES
	byte[] keyA = new byte[8];
	byte[] keyB = new byte[8];
	byte[] keyC = new byte[8];
	for (int i = 0; i < keyA.length; i++){
		keyA[i] = (byte) keyString.charAt(i);
		keyB[i] = (byte) keyString.charAt(i+7);
		keyC[i] = (byte) keyString.charAt(i+14);
	}
	
	// Initialize keys to be DES compatible
	key1 = new SecretKeySpec(keyA, "DES");
	key2 = new SecretKeySpec(keyB, "DES");
	key3 = new SecretKeySpec(keyC, "DES");
	
	// Create nonce of 4 bytes
    nonce = new byte[4];
	new SecureRandom().nextBytes(nonce);
	
	// CTR counter byte arrays
	byte[] c1 = { 0, 0, 0, 0};
	byte[] c2 = { 1, 0, 0, 0};
	byte[] c3 = { 2, 0, 0, 0};
	
	// Make initializing vectors (ivs) to work with CTR mode 
	byte[] iv1 = new byte[nonce.length + c1.length];
	System.arraycopy(nonce, 0, iv1, 0, nonce.length); // copy nonce into first 4 bytes
	System.arraycopy(c1, 0, iv1, nonce.length, c1.length); // nonce.length = offset then add IV into last 4 bytes
	
	byte[] iv2 = new byte[nonce.length + c2.length];
	System.arraycopy(nonce, 0, iv2, 0, nonce.length);
	System.arraycopy(c2, 0, iv2, nonce.length, c2.length);
	
	byte[] iv3 = new byte[nonce.length + c3.length];
	System.arraycopy(nonce, 0, iv3, 0, nonce.length);
	System.arraycopy(c3, 0, iv3, nonce.length, c3.length);
	
	// Set new IVs 
	ivs1 = new IvParameterSpec(iv1);
	ivs2 = new IvParameterSpec(iv2);
	ivs3 = new IvParameterSpec(iv3);
	
	// Create Ciphers to work with both DES and CTR modes with padding
    ecipher1 = Cipher.getInstance("DES/CTR/PKCS5Padding");
	ecipher2 = Cipher.getInstance("DES/CTR/PKCS5Padding");
	ecipher3 = Cipher.getInstance("DES/CTR/PKCS5Padding");
  }
  
  public DESCipher(BigInteger Session_key, byte[] nonce1) throws Exception { // Constructor for server
	String keyString = Session_key.toString();
	// Separate session key into 3 separate keys of 8 bytes each to combine to make a 24 byte block for CTR and DES
	byte[] keyA = new byte[8];
	byte[] keyB = new byte[8];
	byte[] keyC = new byte[8];
	for (int i = 0; i < keyA.length; i++){
		keyA[i] = (byte) keyString.charAt(i);
		keyB[i] = (byte) keyString.charAt(i+7);
		keyC[i] = (byte) keyString.charAt(i+14);
	}
	
	// Initialize keys to be DES compatible
	key1 = new SecretKeySpec(keyA, "DES");
	key2 = new SecretKeySpec(keyB, "DES");
	key3 = new SecretKeySpec(keyC, "DES");
	
    nonce = nonce1; // set nonce equal to the nonce provided
	
	// CTR counter byte arrays
	byte[] c1 = { 0, 0, 0, 0};
	byte[] c2 = { 1, 0, 0, 0};
	byte[] c3 = { 2, 0, 0, 0};
	
	// Make initializing vectors (ivs) to work with CTR mode 
	byte[] iv1 = new byte[nonce.length + c1.length];
	System.arraycopy(nonce, 0, iv1, 0, nonce.length); // copy nonce into first 4 bytes
	System.arraycopy(c1, 0, iv1, nonce.length, c1.length); // nonce.length = offset then add IV into last 4 bytes
	
	byte[] iv2 = new byte[nonce.length + c2.length];
	System.arraycopy(nonce, 0, iv2, 0, nonce.length);
	System.arraycopy(c2, 0, iv2, nonce.length, c2.length);
	
	byte[] iv3 = new byte[nonce.length + c3.length];
	System.arraycopy(nonce, 0, iv3, 0, nonce.length);
	System.arraycopy(c3, 0, iv3, nonce.length, c3.length);
	
	// Set new IVs
	ivs1 = new IvParameterSpec(iv1);
	ivs2 = new IvParameterSpec(iv2);
	ivs3 = new IvParameterSpec(iv3);
	
	// Create Ciphers to work with both DES and CTR modes with padding
    ecipher1 = Cipher.getInstance("DES/CTR/PKCS5Padding");
	ecipher2 = Cipher.getInstance("DES/CTR/PKCS5Padding");
	ecipher3 = Cipher.getInstance("DES/CTR/PKCS5Padding");
  }
  
  public byte[] returnNonce() throws Exception {
	return (nonce); // returns nonce so can send to server to sync up encryption with decryption 
  }
  
  public byte[] encrypt(String plaintext) throws Exception {
	// Triple DES Encryption 
    byte[] text = plaintext.getBytes();
	
	ecipher1.init(Cipher.ENCRYPT_MODE, key1, ivs1); // encrypt message with first key
    byte[] textEncrypted1 = ecipher1.doFinal(text);
	
	ecipher2.init(Cipher.DECRYPT_MODE, key2, ivs2); // decrypt the first encryption with the second key
	byte[] textDecrypted = ecipher2.doFinal(textEncrypted1);
	
	ecipher3.init(Cipher.ENCRYPT_MODE, key3, ivs3); // encrypt the second decryption with the third key
    byte[] textEncrypted2 = ecipher3.doFinal(textDecrypted);
	
	return (textEncrypted2); // return cyphertext in bytes
  }
  
   public byte[] decrypt(byte[] ciphertext) throws Exception {
	// Triple DES Decryption 
	ecipher3.init(Cipher.DECRYPT_MODE, key3, ivs3); // decrypt message with third key
    byte[] textDecrypted1 = ecipher3.doFinal(ciphertext);
	
	ecipher2.init(Cipher.ENCRYPT_MODE, key2, ivs2); // encrypt the first decryption with the second key
	byte[] textEncrypted = ecipher2.doFinal(textDecrypted1);
	
	ecipher1.init(Cipher.DECRYPT_MODE, key1, ivs1); // decrypt the second encryption with the first key
    byte[] textDecrypted2 = ecipher1.doFinal(textEncrypted);
	
	return (textDecrypted2); // return decrypted message in bytes
  }
}