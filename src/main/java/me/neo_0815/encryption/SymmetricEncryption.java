package me.neo_0815.encryption;

import lombok.Getter;
import lombok.NonNull;
import lombok.Setter;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SymmetricEncryption extends Encryption {
	public static final int DEFAULT_LENGTH = 128;
	
	@Getter
	@Setter
	@NonNull
	private SecretKey key;
	
	private void key(final SecretKey key) {
		this.key = key;
		
		initCipher();
	}
	
	public SymmetricEncryption(final String algorithm) {
		this(algorithm, -1);
	}
	
	public SymmetricEncryption(final String algorithm, final int length) {
		super(algorithm);
		
		try {
			final KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
			final SecureRandom rand = new SecureRandom();
			
			keyGen.init(length < 0 ? DEFAULT_LENGTH : length, rand);
			
			key(keyGen.generateKey());
		}catch(final NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}
	
	public SymmetricEncryption(final String algorithm, final SecretKey key) {
		super(algorithm);
		
		key(key);
	}
	
	@Override
	public byte[] encrypt(final byte[] bytes) {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key);
			
			return encode(cipher.doFinal(bytes));
		}catch(final InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
		return new byte[0];
	}
	
	@Override
	public byte[] decrypt(final byte[] bytes) {
		try {
			cipher.init(Cipher.DECRYPT_MODE, key);
			
			return cipher.doFinal(decode(bytes));
		}catch(InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
		}
		
		return new byte[0];
	}
	
	public static SecretKey getKeyFromString(final String key, final String algorithm) {
		return new SecretKeySpec(decode(key), algorithm);
	}
	
	public static SymmetricEncryption generateFromKeyString(final String algorithm, final String key) {
		return new SymmetricEncryption(algorithm, getKeyFromString(key, algorithm));
	}
}
