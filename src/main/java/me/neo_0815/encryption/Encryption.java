package me.neo_0815.encryption;

import lombok.Getter;
import lombok.NonNull;

import java.nio.charset.Charset;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Base64.Decoder;
import java.util.Base64.Encoder;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

public abstract class Encryption {
	private static final Encoder ENCODER = Base64.getEncoder();
	private static final Decoder DECODER = Base64.getDecoder();
	
	@Getter
	protected final String algorithm;
	protected Cipher cipher;
	
	public Encryption(@NonNull final String algorithm) {
		this.algorithm = algorithm;
	}
	
	protected void initCipher() {
		try {
			cipher = Cipher.getInstance(algorithm);
		}catch(NoSuchAlgorithmException | NoSuchPaddingException e) {
			e.printStackTrace();
		}
	}
	
	protected static byte[] encode(final byte[] bytes) {
		return ENCODER.encode(bytes);
	}
	
	protected static byte[] decode(final byte[] bytes) {
		return DECODER.decode(bytes);
	}
	
	protected static byte[] decode(final String text) {
		try {
			return DECODER.decode(text);
		}catch(final IllegalArgumentException e) {
			e.printStackTrace();
		}
		
		return new byte[0];
	}
	
	protected static byte[] decode(final String text, final Charset charset) {
		try {
			return DECODER.decode(text.getBytes(charset));
		}catch(final IllegalArgumentException e) {
			e.printStackTrace();
		}
		
		return new byte[0];
	}
	
	public String encrypt(final String text) {
		return encrypt(text, Charset.defaultCharset());
	}
	
	public String encrypt(final String text, final Charset charset) {
		return new String(encrypt(text.getBytes(charset)), charset);
	}
	
	public abstract byte[] encrypt(byte[] bytes);
	
	public String decrypt(final String text) {
		return decrypt(text, Charset.defaultCharset());
	}
	
	public String decrypt(final String text, final Charset charset) {
		return new String(decrypt(text.getBytes(charset)), charset);
	}
	
	public abstract byte[] decrypt(byte[] bytes);
}
