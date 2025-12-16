package com.project021.demo1.controller;

import com.project021.demo1.model.User;
import javafx.fxml.FXML;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import javafx.stage.Stage;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.project021.demo1.database.Database;

import javax.crypto.spec.SecretKeySpec;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;

public class MainController {

    @FXML private TextArea inputTextArea;
    @FXML private TextArea outputTextArea;
    @FXML private ComboBox<String> algorithmComboBox;
    @FXML private Button logoutButton;

    private User currentUser;

    private final Database database = new Database();

    private SecretKey aesKey;
    private KeyPair rsaKeyPair;
    private SecretKey blowfishKey;

    private static final String AES = "AES";
    private static final String RSA = "RSA";
    private static final String BLOWFISH = "Blowfish";

    private SecretKey masterKey;


    private static final Logger logger = Logger.getLogger(MainController.class.getName());

    public static void generateInitialKeysAndSave(User user, Database database) {
        try {
            // Генерация мастер-ключа
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey masterKey = keyGen.generateKey();
            String encodedMasterKey = Base64.getEncoder().encodeToString(masterKey.getEncoded());
            database.saveMasterKeyForUser(user, encodedMasterKey);

            KeyGenerator aesKeyGen = KeyGenerator.getInstance("AES");
            aesKeyGen.init(128);
            SecretKey aesKey = aesKeyGen.generateKey();

            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance("RSA");
            rsaKeyGen.initialize(2048);
            KeyPair rsaKeyPair = rsaKeyGen.generateKeyPair();

            KeyGenerator blowfishKeyGen = KeyGenerator.getInstance("Blowfish");
            blowfishKeyGen.init(128);
            SecretKey blowfishKey = blowfishKeyGen.generateKey();

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, masterKey);
            String encryptedAESKey = Base64.getEncoder().encodeToString(cipher.doFinal(aesKey.getEncoded()));
            String encryptedRSAPublicKey = Base64.getEncoder().encodeToString(cipher.doFinal(rsaKeyPair.getPublic().getEncoded()));
            String encryptedRSAPrivateKey = Base64.getEncoder().encodeToString(cipher.doFinal(rsaKeyPair.getPrivate().getEncoded()));
            String encryptedBlowfishKey = Base64.getEncoder().encodeToString(cipher.doFinal(blowfishKey.getEncoded()));

            database.saveUserKeys(user, encryptedAESKey, encryptedRSAPublicKey, encryptedRSAPrivateKey, encryptedBlowfishKey);
        } catch (Exception e) {
            Logger.getLogger(MainController.class.getName()).log(Level.SEVERE, "Failed to generate and save initial keys", e);
            throw new RuntimeException("Failed to generate and save initial keys: " + e.getMessage(), e);
        }
    }

    @FXML
    public void initialize() {
        algorithmComboBox.getItems().addAll(AES, RSA, BLOWFISH);
        algorithmComboBox.getSelectionModel().selectFirst();
        generateKeys();
    }

    public void setCurrentUser(User user) {
        this.currentUser = user;
        this.masterKey = getOrCreateMasterKey(user);

        System.out.println("Logged in as: " + user.getUsername());
        database.loadUserKeys(user);
        loadOrGenerateKeys();
    }

    @FXML
    private void handleCopyInput() {
        String text = inputTextArea.getText();
        if (text != null && !text.isEmpty()) {
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(text);
            clipboard.setContent(content);
            logger.info("Input text copied to clipboard");
        } else {
            showError("Input text is empty");
        }
    }

    @FXML
    private void handleCopyOutput() {
        String text = outputTextArea.getText();
        if (text != null && !text.isEmpty()) {
            Clipboard clipboard = Clipboard.getSystemClipboard();
            ClipboardContent content = new ClipboardContent();
            content.putString(text);
            clipboard.setContent(content);
            logger.info("Output text copied to clipboard");
        } else {
            showError("Output text is empty");
        }
    }

    private SecretKey getOrCreateMasterKey(User user) {
        try {
            String encodedKey = loadMasterKeyFromDatabase(user);
            if (encodedKey != null) {
                byte[] decoded = Base64.getDecoder().decode(encodedKey);
                return new SecretKeySpec(decoded, "AES");
            } else {
                KeyGenerator keyGen = KeyGenerator.getInstance("AES");
                keyGen.init(256);
                SecretKey newKey = keyGen.generateKey();
                saveMasterKeyToDatabase(user, Base64.getEncoder().encodeToString(newKey.getEncoded()));
                return newKey;
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to load or generate master key", e);
            showError("Failed to load or generate master key: " + e.getMessage());
            throw new RuntimeException(e);
        }
    }

    private String loadMasterKeyFromDatabase(User user) {
        return database.loadMasterKeyForUser(user);
    }

    private void saveMasterKeyToDatabase(User user, String encodedKey) {
        database.saveMasterKeyForUser(user, encodedKey);
    }

    private void generateKeys() {
        try {
            KeyGenerator aesKeyGen = KeyGenerator.getInstance(AES);
            aesKeyGen.init(128);
            aesKey = aesKeyGen.generateKey();

            KeyPairGenerator rsaKeyGen = KeyPairGenerator.getInstance(RSA);
            rsaKeyGen.initialize(2048);
            rsaKeyPair = rsaKeyGen.generateKeyPair();

            KeyGenerator blowfishKeyGen = KeyGenerator.getInstance(BLOWFISH);
            blowfishKeyGen.init(128);
            blowfishKey = blowfishKeyGen.generateKey();

        } catch (NoSuchAlgorithmException e) {
            logger.log(Level.SEVERE, "Key generation failed", e);
            showError("Key generation failed: " + e.getMessage());
        }
    }

    private void saveKeysToDatabase() throws Exception {
        String encryptedAESKey = encryptKey(aesKey.getEncoded());
        String encryptedRSAPublicKey = encryptKey(rsaKeyPair.getPublic().getEncoded());
        String encryptedRSAPrivateKey = encryptKey(rsaKeyPair.getPrivate().getEncoded());
        String encryptedBlowfishKey = encryptKey(blowfishKey.getEncoded());

        database.saveUserKeys(currentUser, encryptedAESKey, encryptedRSAPublicKey, encryptedRSAPrivateKey, encryptedBlowfishKey);
    }

    private SecretKey decryptKey(String encryptedKey, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, masterKey);
        byte[] decodedKey = Base64.getDecoder().decode(encryptedKey);
        byte[] decryptedKey = cipher.doFinal(decodedKey);
        return new SecretKeySpec(decryptedKey, algorithm);
    }

    private void loadKeysFromDatabase() throws Exception {
        try {
            if (currentUser.getEncryptedAESKey() == null ||
                    currentUser.getEncryptedRSAPublicKey() == null ||
                    currentUser.getEncryptedRSAPrivateKey() == null ||
                    currentUser.getEncryptedBlowfishKey() == null) {
                throw new IllegalStateException("One or more keys are missing in the database");
            }
            aesKey = decryptKey(currentUser.getEncryptedAESKey(), "AES");
            rsaKeyPair = decryptRSAKeyPair(currentUser.getEncryptedRSAPublicKey(), currentUser.getEncryptedRSAPrivateKey());
            blowfishKey = decryptKey(currentUser.getEncryptedBlowfishKey(), "Blowfish");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Failed to load keys from database", e);
            throw new Exception("Failed to load keys from database: " + e.getMessage(), e);
        }
    }

    private void loadOrGenerateKeys() {
        try {
            if (currentUser.getEncryptedAESKey() == null ||
                    currentUser.getEncryptedRSAPublicKey() == null ||
                    currentUser.getEncryptedRSAPrivateKey() == null ||
                    currentUser.getEncryptedBlowfishKey() == null) {

                generateKeys();
                saveKeysToDatabase();
            } else {
                loadKeysFromDatabase();
            }
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error loading or generating keys", e);
            showError("Error loading or generating keys: " + e.getMessage());
        }
    }

    private String encryptKey(byte[] keyBytes) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, masterKey);
        byte[] encrypted = cipher.doFinal(keyBytes);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private KeyPair decryptRSAKeyPair(String encryptedPublicKey, String encryptedPrivateKey) throws Exception {
        if (encryptedPublicKey == null || encryptedPrivateKey == null) {
            throw new IllegalArgumentException("Missing RSA keys in database");
        }
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, masterKey);

        byte[] decodedPublicKey = Base64.getDecoder().decode(encryptedPublicKey);
        byte[] decryptedPublicKey = cipher.doFinal(decodedPublicKey);
        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(decryptedPublicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKey publicKey = (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
        byte[] decodedPrivateKey = Base64.getDecoder().decode(encryptedPrivateKey);
        byte[] decryptedPrivateKey = cipher.doFinal(decodedPrivateKey);
        PKCS8EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(decryptedPrivateKey);
        RSAPrivateKey privateKey = (RSAPrivateKey) keyFactory.generatePrivate(privateKeySpec);

        return new KeyPair(publicKey, privateKey);
    }

    @FXML
    private void handleEncrypt() {
        try {
            String algorithm = algorithmComboBox.getValue();
            String inputText = inputTextArea.getText();
            if (inputText == null || inputText.isEmpty()) {
                showError("Input text is empty");
                return;
            }
            String encryptedText = encrypt(inputText, algorithm);
            outputTextArea.setText(encryptedText);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Encryption error for algorithm: " + algorithmComboBox.getValue(), e);
            showError("Encryption error: " + e.getMessage());
        }
    }

    @FXML
    private void handleDecrypt() {
        try {
            String algorithm = algorithmComboBox.getValue();
            String inputText = inputTextArea.getText();
            String decryptedText = decrypt(inputText, algorithm);
            outputTextArea.setText(decryptedText);
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Decryption error", e);
            showError("Decryption error: " + e.getMessage());
        }
    }

    @FXML
    private void handleLogout() {
        try {
            FXMLLoader loader = new FXMLLoader(getClass().getResource("/com/project021/demo1/views/auth.fxml"));
            Parent root = loader.load();
            Stage stage = new Stage();
            stage.setTitle("Crypto App - Login");
            stage.setScene(new Scene(root));
            stage.show();

            Stage currentStage = (Stage) logoutButton.getScene().getWindow();
            currentStage.close();
        } catch (Exception e) {
            logger.log(Level.SEVERE, "Error loading login window during logout", e);
            showError("Error logging out: " + e.getMessage());
        }
    }

    private String encrypt(String input, String algorithm) throws Exception {
        return switch (algorithm) {
            case AES -> encryptAES(input);
            case RSA -> encryptRSA(input);
            case BLOWFISH -> encryptBlowfish(input);
            default -> throw new IllegalArgumentException("Unsupported algorithm");
        };
    }

    private String decrypt(String input, String algorithm) throws Exception {
        return switch (algorithm) {
            case AES -> decryptAES(input);
            case RSA -> decryptRSA(input);
            case BLOWFISH -> decryptBlowfish(input);
            default -> throw new IllegalArgumentException("Unsupported algorithm");
        };
    }

    private String encryptAES(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey);
        byte[] encrypted = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptAES(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey);
        byte[] decoded = Base64.getDecoder().decode(input);
        return new String(cipher.doFinal(decoded));
    }

    private String encryptRSA(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, rsaKeyPair.getPublic());
        byte[] encrypted = cipher.doFinal(input.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptRSA(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
        byte[] decoded = Base64.getDecoder().decode(input);
        return new String(cipher.doFinal(decoded));
    }

    private String encryptBlowfish(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, blowfishKey);
        byte[] encrypted = cipher.doFinal(input.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    private String decryptBlowfish(String input) throws Exception {
        Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, blowfishKey);
        byte[] decoded = Base64.getDecoder().decode(input);
        return new String(cipher.doFinal(decoded));
    }

    private void showError(String message) {
        Alert alert = new Alert(Alert.AlertType.ERROR);
        alert.setTitle("Error");
        alert.setHeaderText(null);
        alert.setContentText(message);
        alert.showAndWait();
    }
}
