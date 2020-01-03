package com.arrobaautowired.chyperjava;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import lombok.extern.slf4j.Slf4j;

@SpringBootApplication

public class ChyperJavaApplication implements CommandLineRunner {

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
		PGPEnctryptionService.encryptFile("/Users/jose/PROYECTOS/VARIOS/chyper-java/src/main/resources/files/encripted", "/Users/jose/PROYECTOS/VARIOS/chyper-java/src/main/resources/files/plain.txt", "/Users/jose/PROYECTOS/VARIOS/chyper-java/src/main/resources/keys/public.asc", Boolean.FALSE, Boolean.FALSE);
	}
}
