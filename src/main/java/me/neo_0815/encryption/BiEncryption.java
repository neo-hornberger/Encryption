package me.neo_0815.encryption;

import lombok.NonNull;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class BiEncryption extends Encryption {
	private final AsymmetricEncryption asymmetric;
	private SymmetricEncryption symmetric;
	
	private String asymmetricAlgorithm, symmetricAlgorithm;
	
	private void setAlgorithms(@NonNull final String asymmetricAlgorithm, @NonNull final String symmetricAlgorithm) {
		this.asymmetricAlgorithm = asymmetricAlgorithm;
		this.symmetricAlgorithm = symmetricAlgorithm;
	}
	
	public BiEncryption(final String asymmetricAlgorithm, final String symmetricAlgorithm) {
		this(asymmetricAlgorithm, -1, symmetricAlgorithm, -1);
	}
	
	public BiEncryption(final String asymmetricAlgorithm, final int asymmetricLength, final String symmetricAlgorithm, final int symmetricLength) {
		super(asymmetricAlgorithm + "|" + symmetricAlgorithm);
		setAlgorithms(asymmetricAlgorithm, symmetricAlgorithm);
		
		asymmetric = new AsymmetricEncryption(asymmetricAlgorithm, asymmetricLength);
		symmetric = new SymmetricEncryption(symmetricAlgorithm, symmetricLength);
	}
	
	public BiEncryption(final String asymmetricAlgorithm, final PublicKey publicKey, final String symmetricAlgorithm) {
		this(asymmetricAlgorithm, publicKey, symmetricAlgorithm, -1);
	}
	
	public BiEncryption(final String asymmetricAlgorithm, final PublicKey publicKey, final String symmetricAlgorithm, final int symmetricLength) {
		super(asymmetricAlgorithm + "|" + symmetricAlgorithm);
		setAlgorithms(asymmetricAlgorithm, symmetricAlgorithm);
		
		asymmetric = new AsymmetricEncryption(asymmetricAlgorithm, publicKey);
		symmetric = new SymmetricEncryption(symmetricAlgorithm, symmetricLength);
	}
	
	public BiEncryption(final String asymmetricAlgorithm, final PublicKey publicKey, final String symmetricAlgorithm, final SecretKey key) {
		super(asymmetricAlgorithm + "|" + symmetricAlgorithm);
		setAlgorithms(asymmetricAlgorithm, symmetricAlgorithm);
		
		asymmetric = new AsymmetricEncryption(asymmetricAlgorithm, publicKey);
		symmetric = new SymmetricEncryption(symmetricAlgorithm, key);
	}
	
	public BiEncryption(final String asymmetricAlgorithm, final PublicKey publicKey, final PrivateKey privateKey, final String symmetricAlgorithm, final String encryptedKey) {
		this(asymmetricAlgorithm, new KeyPair(publicKey, privateKey), symmetricAlgorithm, encryptedKey);
	}
	
	public BiEncryption(final String asymmetricAlgorithm, final KeyPair keyPair, final String symmetricAlgorithm, final String encryptedKey) {
		super(asymmetricAlgorithm + "|" + symmetricAlgorithm);
		setAlgorithms(asymmetricAlgorithm, symmetricAlgorithm);
		
		asymmetric = new AsymmetricEncryption(asymmetricAlgorithm, keyPair);
		setEncryptedSymmetricKey(encryptedKey);
	}
	
	public BiEncryption(final String asymmetricAlgorithm, final PublicKey publicKey, final PrivateKey privateKey, final String symmetricAlgorithm, final SecretKey key) {
		this(asymmetricAlgorithm, new KeyPair(publicKey, privateKey), symmetricAlgorithm, key);
	}
	
	public BiEncryption(final String asymmetricAlgorithm, final KeyPair keyPair, final String symmetricAlgorithm, final SecretKey key) {
		super(asymmetricAlgorithm + "|" + symmetricAlgorithm);
		setAlgorithms(asymmetricAlgorithm, symmetricAlgorithm);
		
		asymmetric = new AsymmetricEncryption(asymmetricAlgorithm, keyPair);
		symmetric = new SymmetricEncryption(symmetricAlgorithm, key);
	}
	
	@Override
	public byte[] encrypt(final byte[] bytes) {
		return symmetric.encrypt(bytes);
	}
	
	@Override
	public byte[] decrypt(final byte[] bytes) {
		return symmetric.decrypt(bytes);
	}
	
	public KeyPair getAsymmetricKeyPair() {
		return asymmetric.getKeyPair();
	}
	
	public void setAsymmetricKeyPair(final KeyPair keyPair) {
		asymmetric.setKeyPair(keyPair);
	}
	
	public SecretKey getSymmetricKey() {
		return symmetric.getKey();
	}
	
	public void setSymmetricKey(final SecretKey key) {
		symmetric.setKey(key);
	}
	
	public String getEncryptedSymmetricKey() {
		return new String(asymmetric.encrypt(encode(symmetric.getKey().getEncoded())));
	}
	
	public void setEncryptedSymmetricKey(final String encryptedKey) {
		symmetric.setKey(SymmetricEncryption.getKeyFromString(asymmetric.decrypt(encryptedKey), symmetricAlgorithm));
	}
	
	public String getAsymmetricAlgorithm() {
		return asymmetricAlgorithm;
	}
	
	public String getSymmetricAlgorithm() {
		return symmetricAlgorithm;
	}
}
