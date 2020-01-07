package com.arrobaautowired.chyperjava;

import java.security.Security;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class ChyperJavaApplication implements CommandLineRunner {

	private static final String ENCRYPTED_FILE = "/Users/jose/PROYECTOS/VARIOS/chyper-java/src/main/resources/files/encripted.bt";
	private static final String REGULAR_FILE = "/Users/jose/PROYECTOS/VARIOS/chyper-java/src/main/resources/files/plain.txt";
	private static final String DECRYPTED_FILE = "/Users/jose/PROYECTOS/VARIOS/chyper-java/src/main/resources/files/plain-decrypted.txt";
	private static final String PUBLIC_KEY_FILE = "/Users/jose/PROYECTOS/VARIOS/chyper-java/src/main/resources/keys/public.asc";
	private static final String PRIVATE_KEY_FILE = "/Users/jose/PROYECTOS/VARIOS/chyper-java/src/main/resources/keys/private.asc";
	private static final String PASSWORD = "Cl@veFácil001?";

	public static void main(String[] args) {
		SpringApplication.run(ChyperJavaApplication.class, args);
	}

	/**
	 * Callback used to run the bean.
	 *
	 * @param args incoming main method arguments
	 * @throws Exception on error
	 */
	@Override
	public void run(String... args) throws Exception {
		int maxKeySize = javax.crypto.Cipher.getMaxAllowedKeyLength("AES");
		System.out.println(maxKeySize);
		Security.addProvider(new BouncyCastleProvider());
		PGPEnctryptionService.encryptFile(ENCRYPTED_FILE, REGULAR_FILE, PUBLIC_KEY_FILE, Boolean.FALSE, Boolean.FALSE);
		PGPEnctryptionService.decryptFile(ENCRYPTED_FILE,PRIVATE_KEY_FILE, PASSWORD.toCharArray(),DECRYPTED_FILE );
	}
}
