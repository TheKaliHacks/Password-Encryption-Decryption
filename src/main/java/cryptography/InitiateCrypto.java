package cryptography;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Base64;
import java.util.Properties;

public class InitiateCrypto {
    private static final String CONFIG_FILE = "src/main/java/cryptography/config.properties";
    private static String decryptedPassword;

    public static void main(String[] args) {
        // Read password, secret key, and initialization vector from configuration file
        String encryptedPassword = readEncryptedPasswordFromConfigFile();
        SecretKey secretKey = readSecretKeyFromConfigFile();
        byte[] initializationVector = readInitializationVectorFromConfigFile();

        // Decrypt password
        try {
            decryptedPassword = PasswordDecryptor.decrypt(encryptedPassword, secretKey, initializationVector);
        } catch (RuntimeException e) {
            // Handle decryption failure
            System.err.println("Failed to decrypt password: " + e.getMessage());
            return;
        }

        // Display decrypted password
        //System.out.println("Decrypted password: " + decryptedPassword);

    }

    /**
     * Reads the encrypted password from the configuration file.
     *
     * @return The encrypted password
     * @throws RuntimeException If an error occurs while reading the configuration file
     */
    private static String readEncryptedPasswordFromConfigFile() {
        try (FileInputStream fileInputStream = new FileInputStream(CONFIG_FILE)) {
            Properties properties = new Properties();
            properties.load(fileInputStream);
            return properties.getProperty("password");
        } catch (IOException e) {
            throw new RuntimeException("Failed to read the encrypted password from the configuration file.", e);
        }
    }

    /**
     * Reads the secret key from the configuration file.
     *
     * @return The secret key
     * @throws RuntimeException If an error occurs while reading the configuration file or if the secret key format is invalid
     */
    private static SecretKey readSecretKeyFromConfigFile() {
        try (FileInputStream fileInputStream = new FileInputStream(CONFIG_FILE)) {
            Properties properties = new Properties();
            properties.load(fileInputStream);
            String encodedKey = properties.getProperty("secretKey");
            try {
                byte[] keyBytes = Base64.getDecoder().decode(encodedKey);
                return new SecretKeySpec(keyBytes, "AES");
            } catch (IllegalArgumentException e) {
                throw new RuntimeException("Invalid secret key format in the configuration file.", e);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read the secret key from the configuration file.", e);
        }
    }

    /**
     * Reads the initialization vector from the configuration file.
     *
     * @return The initialization vector
     * @throws RuntimeException If an error occurs while reading the configuration file or if the initialization vector format is invalid
     */
    private static byte[] readInitializationVectorFromConfigFile() {
        try (FileInputStream fileInputStream = new FileInputStream(CONFIG_FILE)) {
            Properties properties = new Properties();
            properties.load(fileInputStream);
            String encodedIV = properties.getProperty("initializationVector");
            try {
                return Base64.getDecoder().decode(encodedIV);
            } catch (IllegalArgumentException e) {
                throw new RuntimeException("Invalid initialization vector format in the configuration file.", e);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to read the initialization vector from the configuration file.", e);
        }
    }

    /**
     * Retrieves the decrypted password.
     *
     * @return The decrypted password
     */
    public static String getDecryptedPassword() {
        return decryptedPassword;
    }
}
