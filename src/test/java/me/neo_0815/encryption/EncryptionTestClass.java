package me.neo_0815.encryption;

import java.security.PublicKey;
import java.util.Base64;

public class EncryptionTestClass {
	
	public static void main(final String[] args) {
		final String text = "Hello World! Hello Java! Hello encryption!";
		
		// server
		final AsymmetricEncryption decrypter = new AsymmetricEncryption("RSA", 1024);
		
		// connection
		final PublicKey pubKey = decrypter.getKeyPair().getPublic();
		System.out.println(Base64.getEncoder().encodeToString(pubKey.getEncoded()));
		
		// client
		final BiEncryption encrypter = new BiEncryption("RSA", pubKey, "AES", 128);
		
		// connection
		final String encText = encrypter.encrypt(text), encKey = encrypter.getEncryptedSymmetricKey();
		System.out.println(encText);
		System.out.println(encKey);
		
		// client-connection (server)
		final String decKey = decrypter.decrypt(encKey);
		
		final SymmetricEncryption decrypter2 = SymmetricEncryption.generateFromKeyString("AES", decKey);
		
		final String decText = decrypter2.decrypt(encText);
		System.out.println(decText);
	}
}
