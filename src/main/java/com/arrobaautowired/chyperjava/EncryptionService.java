package com.arrobaautowired.chyperjava;

import java.io.File;
import java.util.Optional;

public interface EncryptionService {

    /**
     * Obtiene un fichero encriptado a partir de un fichero sin encriptar.
     *
     * @param plainFile Fichero sin encriptar.
     * @return Fichero encriptado.
     */
    Optional<File> encryptFile(File plainFile);

    /**
     * Desencriptado del fichero.
     *
     * @param encryptedFile Fichero encriptado.
     * @return Fichero desencriptado.
     */
    Optional<File> decryptFile(File encryptedFile);

}
