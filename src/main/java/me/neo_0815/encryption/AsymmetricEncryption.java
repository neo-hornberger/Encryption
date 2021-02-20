package me.neo_0815.encryption;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.nio.charset.Charset;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;

public class AsymmetricEncryption extends Encryption {
	public static final int DEFAULT_LENGTH = 2048;
	
	@Getter
	@Setter
	@NonNull
	private KeyPair keyPair;
	
	private void keyPair(final KeyPair keyPair) {
		this.keyPair = keyPair;
		
		initCipher();
	}
	
	public AsymmetricEncryption(final String algorithm) {
		this(algorithm, -1);
	}
	
	public AsymmetricEncryption(final String algorithm, final int length) {
		super(algorithm);
		
		try {
			final KeyPairGenerator pairGen = KeyPairGenerator.getInstance(algorithm);
			final SecureRandom rand = new SecureRandom();
			
			pairGen.initialize(length < 0 ? DEFAULT_LENGTH : length, rand);
			
			keyPair(pairGen.generateKeyPair());
		}catch(final NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public AsymmetricEncryption(final String algorithm, final PublicKey publicKey) {
		this(algorithm, publicKey, null);
	}
	
	public AsymmetricEncryption(final String algorithm, final PrivateKey privateKey) {
		this(algorithm, null, privateKey);
	}
	
	public AsymmetricEncryption(final String algorithm, final PublicKey publicKey, final PrivateKey privateKey) {
		this(algorithm, new KeyPair(publicKey, privateKey));
	}
	
	public AsymmetricEncryption(final String algorithm, final KeyPair keyPair) {
		super(algorithm);
		
		keyPair(keyPair);
	}
	
	@Override
	public byte[] encrypt(final byte[] bytes) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
			
			return encode(cipher.doFinal(bytes));
		}catch(final InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
		return new byte[0];
	}
	
	@Override
	public byte[] decrypt(final byte[] bytes) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
			
			return cipher.doFinal(decode(bytes));
		}catch(final InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
		return new byte[0];
	}
	
	public String sign(final String text) {
		return sign(text, Charset.defaultCharset());
	}
	
	public String sign(final String text, final Charset charset) {
		return new String(sign(text.getBytes(charset)), charset);
	}
	
	public byte[] sign(final byte[] bytes) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPrivate());
			
			return encode(cipher.doFinal());
		}catch(final InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
		return new byte[0];
	}
	
	public String verify(final String text) {
		return verify(text, Charset.defaultCharset());
	}
	
	public String verify(final String text, final Charset charset) {
		return new String(verify(text.getBytes(charset)), charset);
	}
	
	public byte[] verify(final byte[] bytes) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, keyPair.getPublic());
			
			return cipher.doFinal(decode(bytes));
		}catch(final InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
		return new byte[0];
	}
}
