import java.io.*;
import java.math.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.util.Arrays;

/**
 * This class provides an implementation of 1024-bit RSA-OAEP.
 *
 * @revised by Mateo Zoto
 * @assignment 4
 * @date December 6th 2013
 */
public class RSATool {
    
    // OAEP constants
    private final static int K = 128;   // size of RSA modulus in bytes
    private final static int K0 = 16;  // K0 in bytes
    private final static int K1 = 16;  // K1 in bytes
    
    // RSA key data
    private BigInteger n;
    private BigInteger e, d, p, q, phiOfN;

    // TODO:  add whatever additional variables that are required to implement 
    // Chinese Remainder decryption as described in Problem 3

    // SecureRandom for OAEP and key generation
    private SecureRandom rnd;

    private boolean debug = false;



    /**
     * Utility for printing protocol messages
     * @param s protocol message to be printed
     */
    private void debug(String s) {
	if(debug) 
	    System.out.println("Debug RSA: " + s);
    }


    /**
     * G(M) = 1st K-K0 bytes of successive applications of SHA1 to M
     */
    private byte[] G(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}


	byte[] output = new byte[K-K0];
	byte[] input = M;

	int numBytes = 0;
	while (numBytes < K-K0) {
          byte[] hashval = sha1.digest(input);

	  if (numBytes + 20 < K-K0)
	      System.arraycopy(hashval,0,output,numBytes,K0);
	  else
	      System.arraycopy(hashval,0,output,numBytes,K-K0-numBytes);

	  numBytes += 20;
	  input = hashval;
	}

	return output;
    }



    /**
     * H(M) = the 1st K0 bytes of SHA1(M)
     */
    private byte[] H(byte[] M) {
        MessageDigest sha1 = null;
	try {
	    sha1 = MessageDigest.getInstance("SHA1");
	}
	catch (NoSuchAlgorithmException e) {
	    System.out.println(e);
	    System.exit(1);
	}

        byte[] hashval = sha1.digest(M);
 
	byte[] output = new byte[K0];
	System.arraycopy(hashval,0,output,0,K0);

	return output;
    }



    /**
     * Construct instance for decryption.  Generates both public and private key data.
     *
     * TODO: implement key generation for RSA as per the description in your write-up.
     *   Include whatever extra data is required to implement Chinese Remainder
     *   decryption as described in Problem 3.
     */
    public RSATool(boolean setDebug) {
	// set the debug flag
	debug = setDebug;
	boolean isPrime = false;
	rnd = new SecureRandom();
	// TODO:  include key generation implementation here (remove init of d)
	d = BigInteger.ONE;
	n = BigInteger.ONE;
	e = BigInteger.ONE;
	int ii = 0; 	//keep track of iterations.
	int jj = 0;
	p = BigInteger.ZERO;
	q = BigInteger.ZERO;
	//calculate a strong prime p and q such that abs(p-q) > 2^80
	BigInteger y = new BigInteger("2").pow(80);
	while(!(p.subtract(q).abs().compareTo(y) == 1)){
	    ii = 0;
	    jj = 0;
	    debug("Computing strong prime p.");
	    while (isPrime == false){
		p = null;
		//primes are set to 1023 because n = pq would not generate 1024 bits. this works, 511 does not.
		p = new BigInteger(1023, rnd);
		p = p.multiply(BigInteger.valueOf(2));
		p = p.add(BigInteger.valueOf(1));
		// p = 2q + 1
		isPrime = p.isProbablePrime(4);
		ii++;
	    }
	    debug("Got p = " + p.toString() + "(took " + String.valueOf(ii) + " iterations)" );
	    debug("Computing strong prime q.");
	    isPrime = false;
	    while (isPrime == false){
		q = null;
		q = new BigInteger(1023, rnd);
		q = q.multiply(BigInteger.valueOf(2));
		q = q.add(BigInteger.valueOf(1));
		// q = 2f + 1
		isPrime = q.isProbablePrime(4);
		jj++;
	    }
	    debug("Got q = " + q.toString() + "(took " + String.valueOf(jj) + " iterations)" );
	}
	//n = p*q
	n = p.multiply(q);
	debug("Using n = " + n);
	
	//phi(n) = p-1 * q-1
	phiOfN =(p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
	debug("phi(n) = " + phiOfN);
	
	//e
	e = BigInteger.valueOf(3);
	while (!(e.gcd(phiOfN).equals(BigInteger.ONE))){
	    e = e.add(BigInteger.ONE);
	    e = e.add(BigInteger.ONE);
	}
	debug("e = "+ e.toString());
	
	//d is the inverse of e mod phi(n)
	d = e.modInverse(phiOfN);
	debug("d = "+ d.toString());
    }


    /**
     * Construct instance for encryption, with n and e supplied as parameters.  No
     * key generation is performed - assuming that only a public key is loaded
     * for encryption.
     */
    public RSATool(BigInteger new_n, BigInteger new_e, boolean setDebug) {
	// set the debug flag
	debug = setDebug;    

	// initialize random number generator
	rnd = new SecureRandom();

	n = new_n;
	e = new_e;

	d = p = q = null;
    }



    public BigInteger get_n() {
	return n;
    }

    public BigInteger get_e() {
	return e;
    }
    
    /**
     * Method from : http://www.cs.berkeley.edu/~daw/teaching/cs70-s05/Homeworks/RSA.java
     * XOR's two byte arrays.
     */
    public byte[] xor_byte(byte [] a, byte [] b){
	byte [] r = new byte[a.length];
	for (int i = 0; i < r.length; i++){
	    r[i] = (byte)(a[i]^b[i]);
	}
	return r;
    }

    /**
     * Encrypts the given byte array using RSA-OAEP.
     *
     * TODO: implement RSA encryption
     *
     * @param plaintext  byte array representing the plaintext
     * @throw IllegalArgumentException if the plaintext is longer than K-K0-K1 bytes
     * @return resulting ciphertext
     */
    public byte[] encrypt(byte[] plaintext) {
	// make sure plaintext fits into one block
	if (plaintext.length > K-K0-K1)
	    throw new IllegalArgumentException("plaintext longer than one block");
	BigInteger m;
	byte ciphertext[] = {0};
	debug("In RSA encrypt");
	//keep looping until we get a positive M
	do{    
	    debug("Applying OAEP padding");
	    
	    //Generate a random K0 bit number r.
	    rnd = new SecureRandom();
	    BigInteger rInt = new BigInteger ((K0*8) -1, rnd);
	    byte [] r = rInt.toByteArray();
	    debug("r = " + CryptoUtilities.toHexString(r));
    
	    //Generate g(r)
	    byte [] gOfR = G(r);
	    debug("G(r) = " + CryptoUtilities.toHexString(gOfR));
    
	    //0^k1 bits of 0's to be created
	    byte [] pad = new byte [K1*8];
	    //concatanate the plaintext with the 0 padding (m||0^k)
	    debug("" + plaintext.length);
	    byte[] paddedm = new byte[plaintext.length + pad.length];
	    System.arraycopy(plaintext, 0, paddedm, 0, plaintext.length);
	    System.arraycopy(pad, 0, paddedm, plaintext.length, pad.length);
	    debug ("padded plaintext = " + CryptoUtilities.toHexString(paddedm));
	    
	    //calculate s now that we have g(r) and our (m||0^k)
	    byte[] s = xor_byte(gOfR, paddedm);
	    debug("s = "+ CryptoUtilities.toHexString(s));
	    debug("s length:" + String.valueOf(s.length));

	    
	    //calculate H(s)
	    byte[] hOfS = H(s);
	    debug("H(s) = "+ CryptoUtilities.toHexString(hOfS));
    
	    //t = r xor H(s)
	    byte[] t = xor_byte(hOfS, r);
	    debug("t = "+ CryptoUtilities.toHexString(t));
	    debug("t length:" + String.valueOf(t.length));

	    //(s || t)
	    byte[] st = new byte[s.length + t.length];
	    System.arraycopy(s, 0, st, 0, s.length);
	    System.arraycopy(t, 0, st, s.length, t.length);
	    debug("(s||t) = "+ CryptoUtilities.toHexString(st));
	    
	    //print the message M which is (S||T) 
	    m = new BigInteger(st);
	    debug ("M = " + m.toString());
	}while (!(m.signum() == 1));
	debug("Encrypting M");
	//getting the ciphertext after ensuring that M is NOT negative.
	m = m.modPow(e, n);
	ciphertext = m.toByteArray();
	debug("C = "+ m.toString());
	return ciphertext;
    }


    /**
     * Decrypts the given byte array using RSA.
     *
     * TODO:  implement RSA-OAEP decryption using the Chinese Remainder method described in Problem 3
     *
     * @param ciphertext  byte array representing the ciphertext
     * @throw IllegalArgumentException if the ciphertext is not valid
     * @throw IllegalStateException if the class is not initialized for decryption
     * @return resulting plaintexttext
     */
    public byte[] decrypt(byte[] ciphertext) {
	debug("In RSA decrypt");

	// make sure class is initialized for decryption
	if (d == null)
	    throw new IllegalStateException("RSA class not initialized for decryption");

	BigInteger cipher = new BigInteger(ciphertext);
	debug("Decrypting c = " + cipher.toString());
	BigInteger mprime = cipher.modPow(d, n);
	debug("M = " + mprime.toString());
	byte [] stprime = mprime.toByteArray();
	debug("st = " + CryptoUtilities.toHexString(stprime));
	byte [] s = new byte [K0*7]; //s will always be 112
	byte [] t = new byte [K0]; // 16 bytes for t
	//s
	System.arraycopy(stprime, 0, s, 0, s.length);
	debug("s = " + CryptoUtilities.toHexString(s));
	//t
	System.arraycopy(stprime, s.length, t, 0, t.length);
	debug("t = " + CryptoUtilities.toHexString(t));
	//H(s)
	byte[] hOfS = H(s);
	debug("H(s) = " + CryptoUtilities.toHexString(hOfS));
	//u = t xor h(s)
	byte [] u = xor_byte(t, hOfS);
	debug("u = " + CryptoUtilities.toHexString(u));
	//G(u)
	byte[] gOfU = G(u);
	debug("G(u) = " + CryptoUtilities.toHexString(gOfU));
	//v = s xor G(u)
	byte [] v = xor_byte(s, gOfU);
	debug("v = " + CryptoUtilities.toHexString(v));
	//for now return v
	byte [] pad = new byte [K1*8];
	//verify if the message is fine
	for (int i = 16; i < (v.length); i++){
	    if (v[i] == 0){
		//do nothing; all is fine
	    }
	    else{
		//no padded 0, scream error
		debug("Message has been altered. Program is now failing.");
		return null;
	    }
	}
	debug("Message is OK.");
	return v;
    }
}