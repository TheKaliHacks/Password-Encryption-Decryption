package cryptography;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public class CustomKeyGenerator {

    private static final int KEY_SIZE = 256;

    /**
     * Generates a secret key for encryption/decryption using the AES algorithm.
     *
     * @return The generated secret key
     * @throws RuntimeException If an error occurs during key generation
     */
    public static SecretKey generateSecretKey() {
        try {
            // Create a KeyGenerator instance with the AES algorithm
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

            // Initialize the key generator with the specified key size and a secure random source
            keyGenerator.init(KEY_SIZE, new SecureRandom());

            // Generate and return the secret key
            return keyGenerator.generateKey();
        } catch (NoSuchAlgorithmException e) {
            // Handle any exception that occurs during key generation and rethrow it as a RuntimeException
            throw new RuntimeException("Failed to generate secret key.", e);
        }
    }

    /**
     * Generates an initialization vector (IV) for encryption/decryption.
     *
     * @return The generated initialization vector
     * @throws RuntimeException If an error occurs during initialization vector generation
     */
    public static byte[] generateInitializationVector() {
        try {
            // Create a byte array to hold the initialization vector
            byte[] iv = new byte[16];

            // Generate random bytes for the initialization vector using a secure random source
            SecureRandom secureRandom = new SecureRandom();
            secureRandom.nextBytes(iv);

            // Return the generated initialization vector
            return iv;
        } catch (Exception e) {
            // Handle any exception that occurs during initialization vector generation and rethrow it as a RuntimeException
            throw new RuntimeException("Failed to generate initialization vector.", e);
        }
    }
}
