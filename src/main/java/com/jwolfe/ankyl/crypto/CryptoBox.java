package com.jwolfe.ankyl.crypto;

import java.nio.file.Path;

public interface CryptoBox {
    String getMode();
    void setMode(String mode);

    String getPadding();
    void setPadding(String padding);

    String getTransformation();

    String encrypt(String plainText, String key);
    String decrypt(String cypherText, String key);

    byte[] encryptAsByteArray(String plainText, String key);
    byte[] decryptAsByteArray(String cipherText, String key);

    byte[] decryptAsByteArray(byte[] cypherText, String key);

    boolean encryptFile(String plainTextFilePathString, String key, String cipherTextFilePathString);
    boolean decryptFile(String cipherTextFilePathString, String key, String plainTextFilePathString);

    boolean encryptFile(Path plainTextFilePath, String key, Path cipherTextFilePath);
    boolean decryptFile(Path cipherTextFilePath, String key, Path plainTextFilePath);

    String getFileContentsAsEncryptedString(String plainTextFilePathString, String key);
    String getFileContentsAsDecryptedString(String cipherTextFilePathString, String key);

    String getFileContentsAsEncryptedString(Path plainTextFilePath, String key);
    String getFileContentsAsDecryptedString(Path cipherTextFilePath, String key);

    byte[] getFileContentsAsEncryptedByteArray(String plainTextFilePathString, String key);
    byte[] getFileContentsAsDecryptedByteArray(String cipherTextFilePathString, String key);

    byte[] getFileContentsAsEncryptedByteArray(Path plainTextFilePathString, String key);
    byte[] getFileContentsAsDecryptedByteArray(Path cipherTextFilePathString, String key);
}
