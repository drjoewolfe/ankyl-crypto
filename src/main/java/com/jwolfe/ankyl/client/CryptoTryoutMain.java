package com.jwolfe.ankyl.client;

import com.jwolfe.ankyl.crypto.*;
import com.jwolfe.ankyl.swing.JTextAreaAppender;
import org.apache.commons.io.FilenameUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.swing.*;
import javax.swing.event.ChangeEvent;
import javax.swing.event.ChangeListener;
import java.awt.event.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

public class CryptoTryoutMain {
    private final Logger logger = LogManager.getLogger();

    public JPanel cryptoMainPanel;
    private JTextArea tePlainTextArea;
    private JTextArea teKeyArea;
    private JTextArea teCipherTextArea;
    private JButton encryptButton;
    private JButton decryptButton;
    private JButton cancelButton;
    private JRadioButton AESRadioButton;
    private JRadioButton a3DESRadioButton;
    private JRadioButton AESWrapRadioButton;
    private JRadioButton ARCFOURRadioButton;
    private JRadioButton ECIESRadioButton;
    private JRadioButton GCMRadioButton;
    private JRadioButton RC4RadioButton;
    private JRadioButton RC2RadioButton1;
    private JRadioButton PBERadioButton1;
    private JRadioButton blowfishRadioButton;
    private JRadioButton CCMRadioButton;
    private JRadioButton RC5RadioButton;
    private JRadioButton RSARadioButton;
    private JRadioButton noneRadioButton;
    private JRadioButton CBCRadioButton;
    private JRadioButton CFBRadioButton;
    private JRadioButton CTRRadioButton;
    private JRadioButton CTSRadioButton;
    private JRadioButton ECBRadioButton;
    private JRadioButton OFBRadioButton;
    private JRadioButton PCBCRadioButton;
    private JRadioButton noPaddingRadioButton;
    private JRadioButton ISO20126RadioButton;
    private JRadioButton OAEPRadioButton;
    private JRadioButton PKCS1RadioButton;
    private JRadioButton PKCS5RadioButton;
    private JRadioButton SSL3RadioButton;
    private JRadioButton DESRadioButton;
    private JRadioButton a3DESWrapRadioButton;
    private JTabbedPane modeTabPane;
    private JTextField feSourceFileTextField;
    private JCheckBox feEncryptInPlaceCheckBox;
    private JTextField feOutputDirectoryTextField;
    private JButton fePreviewSourceButton;
    private JTextArea feFileContentsTextArea;
    private JPanel fileEncryptTabPanel;
    private JPanel textEncryptTabPanel;
    private JTextField feKeyOrPasswordForFileTextField;
    private JButton fePreviewTargetButton;
    private JTextField feOutputFileNameTextField;
    private JTextArea outputMessages;
    private JPanel fileDecryptTabPanel;
    private JPanel textDecryptTabPanel;
    private JTextArea tdCipherTextArea;
    private JTextArea tdKeyArea;
    private JTextArea tdPlainTextArea;
    private JTextField fdSourceFileTextField;
    private JTextField fdKeyOrPasswordForFileTextField;
    private JCheckBox fdEncryptInPlaceCheckBox;
    private JTextField fdOutputDirectoryTextField;
    private JTextField fdOutputFileNameTextField;
    private JButton fdPreviewSourceButton;
    private JButton fdPreviewTargetButton;
    private JTextArea fdFileContentsTextArea;

    private enum CyptoTabMode {
        FileEncrypt,
        FileDecrypt,
        TextEncrypt,
        TextDecrypt,
        Unknown
    }

    public CryptoTryoutMain() {

        JTextAreaAppender.addLog4j2TextAreaAppender(this.outputMessages);

        encryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                encrypt();
            }
        });
        decryptButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                decrypt();
            }
        });
        cancelButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                System.exit(0);
            }
        });
        fePreviewSourceButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                previewSourceFile();
            }
        });
        fePreviewTargetButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                previewDestinationFile();
            }
        });


        fdPreviewSourceButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                previewSourceFile();
            }
        });
        fdPreviewTargetButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                previewDestinationFile();
            }
        });

        feSourceFileTextField.addFocusListener(new FocusAdapter() {
            @Override
            public void focusLost(FocusEvent e) {
                super.focusLost(e);
                guessFeOutputFileName();
            }
        });

        modeTabPane.addChangeListener(new ChangeListener() {
            @Override
            public void stateChanged(ChangeEvent e) {
                processTabState();
            }
        });

        feEncryptInPlaceCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                processInPlaceCryptoVisibility();
            }
        });
        fdEncryptInPlaceCheckBox.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                processInPlaceCryptoVisibility();
            }
        });

        processTabState();
    }

    private void processTabState() {
        var mode = getCurrentMode();
        switch (mode) {
            case FileEncrypt: // File - Encrypt
                encryptButton.setVisible(true);
                decryptButton.setVisible(false);

                guessFeOutputFileName();
                processInPlaceCryptoVisibility();

                break;
            case FileDecrypt: // File - Decrypt
            case TextDecrypt: // Text - Decrypt
                encryptButton.setVisible(false);
                decryptButton.setVisible(true);
                break;
            case TextEncrypt: // Text - Encrypt
                encryptButton.setVisible(true);
                decryptButton.setVisible(false);
                break;
        }
    }

    private void processInPlaceCryptoVisibility() {
        var mode = getCurrentMode();
        switch (mode) {
            case FileEncrypt: // File - Encrypt
                if (feEncryptInPlaceCheckBox.isSelected()) {
                    feOutputDirectoryTextField.setEnabled(false);
                    feOutputFileNameTextField.setEnabled(false);
                    fePreviewTargetButton.setEnabled(false);
                } else {
                    feOutputDirectoryTextField.setEnabled(true);
                    feOutputFileNameTextField.setEnabled(true);
                    fePreviewTargetButton.setEnabled(true);
                }

                break;
            case FileDecrypt: // File - Decrypt
                if (fdEncryptInPlaceCheckBox.isSelected()) {
                    fdOutputDirectoryTextField.setEnabled(false);
                    fdOutputFileNameTextField.setEnabled(false);
                    fdPreviewTargetButton.setEnabled(false);
                } else {
                    fdOutputDirectoryTextField.setEnabled(true);
                    fdOutputFileNameTextField.setEnabled(true);
                    fdPreviewTargetButton.setEnabled(true);
                }

                break;
        }
    }

    private CyptoTabMode getCurrentMode() {
        int selectedTabIndex = modeTabPane.getSelectedIndex();
        switch (selectedTabIndex) {
            case 0: // File - Encrypt
                return CyptoTabMode.FileEncrypt;
            case 1: // File - Decrypt
                return CyptoTabMode.FileDecrypt;
            case 2: // Text - Encrypt
                return CyptoTabMode.TextEncrypt;
            case 3: // Text - Decrypt
                return CyptoTabMode.TextDecrypt;
        }

        return CyptoTabMode.Unknown;
    }

    private void encrypt() {
        var mode = getCurrentMode();

        switch (mode) {
            case FileEncrypt: // File - Encrypt
                encryptFileMode();
                break;
            case TextEncrypt: // Text - Encrypt
                encryptTextMode();
                break;
        }
    }

    private void decrypt() {
        var mode = getCurrentMode();

        switch (mode) {
            case FileDecrypt: // File - Encrypt
                decryptFileMode();
                break;
            case TextDecrypt: // Text - Encrypt
                decryptTextMode();
                break;
        }
    }

    private void encryptFileMode() {
        logger.info("Initializing encryption for file mode");

        Path sourceFilePath = validateAndGetFeSourceFilePath();
        if (sourceFilePath == null) {
            return;
        }

        Path destinationFilePath = validateAndGetFeDestinationFilePath();
        if (destinationFilePath == null) {
            return;
        }

        var key = feKeyOrPasswordForFileTextField.getText();

        if (key.trim().equals("")) {
            logger.info("No key or password provided");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "No key or password provided", "Empty key / password", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        var box = getBox();
        logger.info("Encryption: Source file - '" + sourceFilePath + "'");
        logger.info("Encryption: Target file - '" + destinationFilePath + "'");
        int confirmation = JOptionPane.showConfirmDialog(this.cryptoMainPanel, "Encryption:\n" + ""
                + "Source file - '" + sourceFilePath + "'\n"
                + "Target file - '" + destinationFilePath + "'\n"
                + "Crypto settings - '" + box.getTransformation() + "'\n"
                + "\n"
                + "Are you sure you want to proceed ?");

        if (confirmation != 0) {
            logger.info("Encryption cancelled");
            return;
        }

        boolean success = box.encryptFile(sourceFilePath, key, destinationFilePath);
        if (!success) {
            logger.info("Encryption failed");
        }

        logger.info("Encryption complete");
    }

    private void encryptTextMode() {
        logger.info("Initializing encryption for text mode");
        if (tePlainTextArea.getText().trim().equals("")) {
            logger.info("No text to encrypt");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "No text to encrypt", "Empty plain text", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        if (teKeyArea.getText().trim().equals("")) {
            logger.info("No key or password provided");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "No key or password provided", "Empty key / password", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        var box = getBox();
        var plainText = tePlainTextArea.getText();
        var key = teKeyArea.getText();

        teCipherTextArea.setText(box.encrypt(plainText, key));
        logger.info("Encryption complete");
    }

    private void decryptFileMode() {
        logger.info("Initializing decrption for file mode");

        Path sourceFilePath = validateAndGetFdSourceFilePath();
        if (sourceFilePath == null) {
            return;
        }

        Path destinationFilePath = validateAndGetFdDestinationFilePath();
        if (destinationFilePath == null) {
            return;
        }

        var key = fdKeyOrPasswordForFileTextField.getText();

        if (key.trim().equals("")) {
            logger.info("No key or password provided");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "No key or password provided", "Empty key / password", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        var box = getBox();
        logger.info("Decryption: Source file - '" + sourceFilePath + "'");
        logger.info("Decryption: Target file - '" + destinationFilePath + "'");
        int confirmation = JOptionPane.showConfirmDialog(this.cryptoMainPanel, "Decryption\n" + ""
                + "Source file - '" + sourceFilePath + "'\n"
                + "Target file - '" + sourceFilePath + "'\n"
                + "Crypto settings - '" + box.getTransformation() + "'\n"
                + "\n"
                + "Are you sure you want to proceed ?");

        if (confirmation != 0) {
            logger.info("Decryption cancelled");
            return;
        }

        boolean success = box.decryptFile(sourceFilePath, key, destinationFilePath);
        if (!success) {
            logger.info("Decryption failed");
        }

        logger.info("Decryption complete");
    }

    private void decryptTextMode() {
        logger.info("Initializing decryption for text mode");

        if (tdCipherTextArea.getText().trim().equals("")) {
            logger.info("No text to decrypt");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "No text to decrypt", "Empty cypher text", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        if (tdKeyArea.getText().trim().equals("")) {
            logger.info("No key or password provided");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "No key or password provided", "Empty key / password", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        var box = getBox();
        var cipherText = tdCipherTextArea.getText();
        var key = tdKeyArea.getText();

        tdPlainTextArea.setText(box.decrypt(cipherText, key));
        logger.info("Decryption complete");
    }

    private void previewSourceFile() {
        var mode = getCurrentMode();

        switch (mode) {
            case FileEncrypt: // File - Encrypt
                previewSourceFileForEncryptFileMode();
                break;
            case FileDecrypt: // Text - Encrypt
                previewSourceFileForDecryptFileMode();
                break;
        }
    }

    private void previewSourceFileForEncryptFileMode() {
        feFileContentsTextArea.setText("");

        Path sourceFilePath = validateAndGetFeSourceFilePath();
        logger.info("Previewing source file - '" + sourceFilePath.toString() + "'");

        String sourceFileContents = getFeSourceFileContents();
        if (sourceFileContents == null) {
            return;
        }

        feFileContentsTextArea.setText(sourceFileContents);
        feFileContentsTextArea.setCaretPosition(0);
    }

    private void previewSourceFileForDecryptFileMode() {
        fdFileContentsTextArea.setText("");

        Path sourceFilePath = validateAndGetFdSourceFilePath();
        logger.info("Previewing source file - '" + sourceFilePath.toString() + "'");

        String sourceFileContents = getFdSourceFileContents();
        if (sourceFileContents == null) {
            return;
        }

        fdFileContentsTextArea.setText(sourceFileContents);
        fdFileContentsTextArea.setCaretPosition(0);
    }

    private void previewDestinationFile() {
        var mode = getCurrentMode();

        switch (mode) {
            case FileEncrypt: // File - Encrypt
                previewDestinationFileForEncryptFileMode();
                break;
            case FileDecrypt: // Text - Encrypt
                previewDestinationFileForDecryptFileMode();
                break;
        }
    }

    private void previewDestinationFileForEncryptFileMode() {
        feFileContentsTextArea.setText("");

        Path destinationFilePath = validateAndGetFeDestinationFilePath();
        logger.info("Previewing destination file - '" + destinationFilePath.toString() + "'");

        String destinationFileContents = getFeDestinationFileContents();
        if (destinationFileContents == null) {
            return;
        }

        feFileContentsTextArea.setText(destinationFileContents);
        feFileContentsTextArea.setCaretPosition(0);
    }

    private void previewDestinationFileForDecryptFileMode() {
        fdFileContentsTextArea.setText("");

        Path destinationFilePath = validateAndGetFdDestinationFilePath();
        logger.info("Previewing destination file - '" + destinationFilePath.toString() + "'");

        String destinationFileContents = getFdDestinationFileContents();
        if (destinationFileContents == null) {
            return;
        }

        fdFileContentsTextArea.setText(destinationFileContents);
        fdFileContentsTextArea.setCaretPosition(0);
    }

    private String getFeSourceFileContents() {
        Path sourceFilePath = validateAndGetFeSourceFilePath();
        return getSourceFileContents(sourceFilePath);
    }

    private String getFdSourceFileContents() {
        Path sourceFilePath = validateAndGetFdSourceFilePath();
        return getSourceFileContents(sourceFilePath);
    }

    private String getSourceFileContents(Path sourceFilePath) {
        if (sourceFilePath == null) {
            return null;
        }

        String sourceFileContents = null;
        try {
            sourceFileContents = new Scanner(new File(sourceFilePath.toAbsolutePath().toString())).useDelimiter("\\Z").next();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        return sourceFileContents;
    }

    private String getFeDestinationFileContents() {
        Path destinationFilePath = validateAndGetFeDestinationFilePath();
        return getDestinationFileContents(destinationFilePath);
    }

    private String getFdDestinationFileContents() {
        Path destinationFilePath = validateAndGetFdDestinationFilePath();
        return getDestinationFileContents(destinationFilePath);
    }

    private String getDestinationFileContents(Path destinationFilePath) {
        if (destinationFilePath == null) {
            return null;
        }

        if (!Files.exists(destinationFilePath)) {
            String message = "Destination file '" + destinationFilePath.toString() + "' does not exist yet";
            logger.info(message);
            JOptionPane.showMessageDialog(this.cryptoMainPanel, message, "Destination file does not exist", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }

        String destinationFileContents = null;
        try {
            destinationFileContents = new Scanner(new File(destinationFilePath.toAbsolutePath().toString())).useDelimiter("\\Z").next();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        return destinationFileContents;
    }

    private void guessFeOutputFileName() {
        String sourceFilePathString = feSourceFileTextField.getText();
        if (sourceFilePathString.trim().equals("")) {
            return;
        }

        Path sourceFilePath = Paths.get(sourceFilePathString);
        String sourceFileName = sourceFilePath.getFileName().toString();

        String filePart = FilenameUtils.getBaseName(sourceFileName);
        String extension = FilenameUtils.getExtension(sourceFileName);

        String targetFileName = filePart + "." + extension + ".enc";

        feOutputFileNameTextField.setText(targetFileName);
    }

    private Path validateAndGetFeSourceFilePath() {
        String sourceFilePathString = feSourceFileTextField.getText();
        return validateAndGetSourceFilePath(sourceFilePathString);
    }

    private Path validateAndGetFdSourceFilePath() {
        String sourceFilePathString = fdSourceFileTextField.getText();
        return validateAndGetSourceFilePath(sourceFilePathString);
    }

    private Path validateAndGetSourceFilePath(String sourceFilePathString) {
        if (sourceFilePathString.trim().equals("")) {
            logger.info("No source file specified");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "No source file specified", "No file", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }

        Path sourceFilePath = Paths.get(sourceFilePathString);
        if (!Files.exists(sourceFilePath)) {
            logger.info("Invalid path or file does not exist");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "Invalid path or file does not exist", "Invalid path", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }

        return sourceFilePath;
    }

    private Path validateAndGetFeDestinationFilePath() {
        if (feEncryptInPlaceCheckBox.isSelected()) {
            return validateAndGetFeSourceFilePath();
        } else {
            String destinationDirectoryPathString = feOutputDirectoryTextField.getText();
            String destinationFileName = feOutputFileNameTextField.getText();
            return validateAndGetDestinationFilePath(destinationDirectoryPathString, destinationFileName);
        }
    }

    private Path validateAndGetFdDestinationFilePath() {
        if (feEncryptInPlaceCheckBox.isSelected()) {
            return validateAndGetFdSourceFilePath();
        } else {
            String destinationDirectoryPathString = fdOutputDirectoryTextField.getText();
            String destinationFileName = fdOutputFileNameTextField.getText();
            return validateAndGetDestinationFilePath(destinationDirectoryPathString, destinationFileName);
        }
    }

    private Path validateAndGetDestinationFilePath(String destinationDirectoryPathString, String destinationFileName) {
        if (destinationDirectoryPathString.trim().equals("")) {
            logger.info("No target directory specified");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "No target directory specified", "No output directory", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }

        if (destinationFileName.trim().equals("")) {
            logger.info("No destination file name specified");
            JOptionPane.showMessageDialog(this.cryptoMainPanel, "No destination file name specified", "No output file", JOptionPane.INFORMATION_MESSAGE);
            return null;
        }

        File directory = new File(destinationDirectoryPathString);
        if (!directory.exists()) {
            directory.mkdirs();
        }

        return Paths.get(destinationDirectoryPathString, destinationFileName);
    }

    private CryptoBox getBox() {
        String algorithm = getSelectedAlgorithm();
        String mode = getSelectedMode();
        String padding = getSelectedPadding();

        CryptoBox box = null;
        if (CipherAlgorithms.AES.equals(algorithm)) {
            box = new AesBox();
            box.setMode(mode);
            box.setPadding(padding);
        }

        return box;
    }

    private String getSelectedAlgorithm() {
        if (AESRadioButton.isSelected()) {
            return CipherAlgorithms.AES;
        } else if (ARCFOURRadioButton.isSelected()) {
            return CipherAlgorithms.ARCFOUR;
        } else if (ARCFOURRadioButton.isSelected()) {
            return CipherAlgorithms.ARCFOUR;
        } else if (AESWrapRadioButton.isSelected()) {
            return CipherAlgorithms.AES_WRAP;
        } else if (blowfishRadioButton.isSelected()) {
            return CipherAlgorithms.BLOWFISH;
        } else if (CCMRadioButton.isSelected()) {
            return CipherAlgorithms.CCM;
        } else if (DESRadioButton.isSelected()) {
            return CipherAlgorithms.DES;
        } else if (a3DESRadioButton.isSelected()) {
            return CipherAlgorithms.DES_EDE;
        } else if (a3DESWrapRadioButton.isSelected()) {
            return CipherAlgorithms.DES_EDE_WRAP;
        } else if (ECIESRadioButton.isSelected()) {
            return CipherAlgorithms.ECIES;
        } else if (GCMRadioButton.isSelected()) {
            return CipherAlgorithms.GCM;
        } else if (PBERadioButton1.isSelected()) {
            return CipherAlgorithms.PBE;
        } else if (RC2RadioButton1.isSelected()) {
            return CipherAlgorithms.RC2;
        } else if (RC4RadioButton.isSelected()) {
            return CipherAlgorithms.RC4;
        } else if (RC2RadioButton1.isSelected()) {
            return CipherAlgorithms.RC5;
        } else if (RSARadioButton.isSelected()) {
            return CipherAlgorithms.RSA;
        }

        return null;
    }

    private String getSelectedMode() {
        if (noneRadioButton.isSelected()) {
            return CipherModes.NONE;
        } else if (CBCRadioButton.isSelected()) {
            return CipherModes.CBC;
        } else if (CFBRadioButton.isSelected()) {
            return CipherModes.CFB;
        } else if (CTRRadioButton.isSelected()) {
            return CipherModes.CTR;
        } else if (CTSRadioButton.isSelected()) {
            return CipherModes.CTS;
        } else if (ECBRadioButton.isSelected()) {
            return CipherModes.ECB;
        } else if (OFBRadioButton.isSelected()) {
            return CipherModes.OFB;
        } else if (PCBCRadioButton.isSelected()) {
            return CipherModes.PCBC;
        }

        return null;
    }

    private String getSelectedPadding() {
        if (noPaddingRadioButton.isSelected()) {
            return CipherPaddings.NO_PADDING;
        } else if (ISO20126RadioButton.isSelected()) {
            return CipherPaddings.ISO_10126_PADDING;
        } else if (OAEPRadioButton.isSelected()) {
            return CipherPaddings.OAEP_PADDING;
        } else if (PKCS1RadioButton.isSelected()) {
            return CipherPaddings.PKCS1_PADDING;
        } else if (PKCS5RadioButton.isSelected()) {
            return CipherPaddings.PKCS5_PADDING;
        } else if (SSL3RadioButton.isSelected()) {
            return CipherPaddings.SSL3_PADDING;
        }

        return null;
    }
}
