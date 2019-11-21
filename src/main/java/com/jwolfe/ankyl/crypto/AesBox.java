package com.jwolfe.ankyl.crypto;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class AesBox extends CryptoBoxBase {
    private final Logger logger = LogManager.getLogger();

    public AesBox() {
        this.algorithm = CipherAlgorithms.AES;
        this.mode = CipherModes.CBC;
        this.padding = CipherPaddings.PKCS5_PADDING;
    }

    public AesBox(final String mode) {
        this.mode = mode;
    }

    @Override
    public String encrypt(final String plainText, final String key) {
        String cipherText = null;

        try {
            Cipher cipher = getEncryptionCipher(key);
            cipherText = Base64.getEncoder().encodeToString(cipher.doFinal(plainText.getBytes("UTF-8")));
        } catch (Exception e) {
            logger.error("Error while encrypting: " + e.toString());
        }

        return cipherText;
    }

    @Override
    public byte[] encryptAsByteArray(final String plainText, final String key) {
        byte[] cipherText = null;

        try {
            Cipher cipher = getEncryptionCipher(key);
            cipherText = cipher.doFinal(plainText.getBytes("UTF-8"));
        } catch (Exception e) {
            logger.error("Error while encrypting: " + e.toString());
        }

        return cipherText;
    }

    @Override
    public String decrypt(final String cipherText, final String key) {
        String plainText = null;

        try {
            Cipher cipher = getDecryptionCipher(key);
            plainText = new String(cipher.doFinal(Base64.getDecoder().decode(cipherText)));
        } catch (Exception e) {
            logger.error("Error while decrypting: " + e.toString());
        }

        return plainText;
    }

    @Override
    public byte[] decryptAsByteArray(final String cipherText, final String key) {
        byte[] plainText = null;

        try {
            Cipher cipher = getDecryptionCipher(key);
            plainText = cipher.doFinal(Base64.getDecoder().decode(cipherText));
        } catch (Exception e) {
            logger.error("Error while decrypting: " + e.toString());
        }

        return plainText;
    }

    @Override
    public byte[] decryptAsByteArray(byte[] cypherText, final String key) {
        byte[] plainText = null;

        try {
            Cipher cipher = getDecryptionCipher(key);
            plainText = cipher.doFinal(cypherText);
        } catch (Exception e) {
            logger.error("Error while decrypting: " + e.toString());
        }

        return plainText;
    }

    @Override
    public boolean encryptFile(final String plainTextFilePathString, final String key, final String cipherTextFilePathString) {
        var cipherText = getFileContentsAsEncryptedString(plainTextFilePathString, key);
        if (cipherText == null) {
            return false;
        }

        writeToFile(cipherTextFilePathString, cipherText);
        return true;
    }

    @Override
    public boolean decryptFile(final String cipherTextFilePathString, final String key, final String plainTextFilePathString) {
        var plainText = getFileContentsAsDecryptedString(cipherTextFilePathString, key);
        if (plainText == null) {
            return false;
        }

        writeToFile(plainTextFilePathString, plainText);
        return true;
    }

    @Override
    public boolean encryptFile(Path plainTextFilePath, String key, Path cipherTextFilePath) {
        return encryptFile(plainTextFilePath.toString(), key, cipherTextFilePath.toString());
    }

    @Override
    public boolean decryptFile(Path cipherTextFilePath, String key, Path plainTextFilePath) {
        return decryptFile(cipherTextFilePath.toString(), key, plainTextFilePath.toString());
    }

    @Override
    public String getFileContentsAsEncryptedString(String plainTextFilePathString, String key) {
        if (key.trim().equals("")) {
            logger.error("No key or password provided");
            return null;
        }

        String plainText = getFileContents(plainTextFilePathString);
        if (plainText == null) {
            return null;
        }

        if (plainText.trim().equals("")) {
            logger.error("Source file does not contain any text");
            return null;
        }

        return encrypt(plainText, key);
    }

    @Override
    public String getFileContentsAsDecryptedString(String cipherTextFilePathString, String key) {
        if (key.trim().equals("")) {
            logger.error("No key or password provided");
            return null;
        }

        String cipherText = getFileContents(cipherTextFilePathString);
        if (cipherText == null) {
            return null;
        }

        if (cipherText.trim().equals("")) {
            logger.error("Source file does not contain any text");
            return null;
        }

        return decrypt(cipherText, key);
    }

    @Override
    public String getFileContentsAsEncryptedString(Path plainTextFilePath, String key) {
        return getFileContentsAsEncryptedString(plainTextFilePath.toString(), key);
    }

    @Override
    public String getFileContentsAsDecryptedString(Path cipherTextFilePath, String key) {
        return getFileContentsAsDecryptedString(cipherTextFilePath.toString(), key);
    }

    @Override
    public byte[] getFileContentsAsEncryptedByteArray(String plainTextFilePathString, String key) {
        if (key.trim().equals("")) {
            logger.error("No key or password provided");
            return null;
        }

        String plainText = getFileContents(plainTextFilePathString);
        if (plainText == null) {
            return null;
        }

        if (plainText.trim().equals("")) {
            logger.error("Source file does not contain any text");
            return null;
        }

        return encryptAsByteArray(plainText, key);
    }

    @Override
    public byte[] getFileContentsAsDecryptedByteArray(String cipherTextFilePathString, String key) {
        if (key.trim().equals("")) {
            logger.error("No key or password provided");
            return null;
        }

        String cipherText = getFileContents(cipherTextFilePathString);
        if (cipherText == null) {
            return null;
        }

        if (cipherText.trim().equals("")) {
            logger.error("Source file does not contain any text");
            return null;
        }

        return decryptAsByteArray(cipherText, key);
    }

    @Override
    public byte[] getFileContentsAsEncryptedByteArray(Path plainTextFilePathString, String key) {
        return getFileContentsAsEncryptedByteArray(plainTextFilePathString.toString(), key);
    }

    @Override
    public byte[] getFileContentsAsDecryptedByteArray(Path cipherTextFilePathString, String key) {
        return getFileContentsAsDecryptedByteArray(cipherTextFilePathString.toString(), key);
    }

    private SecretKeySpec getAesKey(String inputKey) {
        SecretKeySpec spec = null;

        try {
            byte[] keyBytes = inputKey.getBytes("UTF-8");
            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            keyBytes = sha.digest(keyBytes);
            keyBytes = Arrays.copyOf(keyBytes, 16);
            spec = new SecretKeySpec(keyBytes, this.algorithm);
        } catch (NoSuchAlgorithmException | UnsupportedEncodingException e) {
            e.printStackTrace();
        }

        return spec;
    }

    private String getFileContents(String filePathString) {
        if (filePathString.trim().equals("")) {
            logger.error("No file specified to read");
            return null;
        }

        Path filePath = Paths.get(filePathString);
        if (!Files.exists(filePath)) {
            logger.error("Invalid path or file does not exist - '" + filePathString + "'");
            return null;
        }

        String fileContents = null;
        try {
            fileContents = new Scanner(new File(filePathString)).useDelimiter("\\Z").next();
        } catch (FileNotFoundException e) {
            logger.error("Error while reading file - '" + filePathString + "' - " + e.toString());
        }

        return fileContents;
    }

    private void writeToFile(String filePathString, String content) {
        if (filePathString.trim().equals("")) {
            logger.error("No file specified");
            return;
        }

        File file = new File(filePathString);
        File directory = file.getParentFile();
        if (!directory.exists()) {
            directory.mkdirs();
        }

        try {
            Files.write(Paths.get(filePathString), content.getBytes());
        } catch (IOException e) {
            logger.error("Error while writing to file - " + e.toString());
        }
    }

    private Cipher getEncryptionCipher(String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        var keySpec = getAesKey(key);
        Cipher cipher = Cipher.getInstance(this.getTransformation());
        if (this.mode.equals(CipherModes.CBC)) {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(new byte[16]));
        } else {
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        }

        return cipher;
    }

    private Cipher getDecryptionCipher(String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, InvalidAlgorithmParameterException {
        var keySpec = getAesKey(key);
        Cipher cipher = Cipher.getInstance(this.getTransformation());
        if (this.mode.equals(CipherModes.CBC)) {
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(new byte[16]));
        } else {
            cipher.init(Cipher.DECRYPT_MODE, keySpec);
        }

        return cipher;
    }
}
