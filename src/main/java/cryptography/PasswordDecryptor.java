package cryptography;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class PasswordDecryptor {

    private static final String ENCRYPTION_ALGORITHM = "AES/CBC/PKCS5Padding";

    /**
     * Decrypts the encrypted password using the provided secret key and initialization vector.
     *
     * @param encryptedPassword    The encrypted password to be decrypted
     * @param secretKey             The secret key used for decryption
     * @param initializationVector The initialization vector used for decryption
     * @return The decrypted password
     * @throws RuntimeException If an error occurs during decryption
     */
    public static String decrypt(String encryptedPassword, SecretKey secretKey, byte[] initializationVector) {
        try {
            // Create a cipher instance with the specified encryption algorithm
            Cipher cipher = Cipher.getInstance(ENCRYPTION_ALGORITHM);

            // Create an initialization vector parameter specification
            IvParameterSpec ivParameterSpec = new IvParameterSpec(initializationVector);

            // Initialize the cipher with the decryption mode, secret key, and initialization vector
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParameterSpec);

            // Decode the Base64 encoded encrypted password
            byte[] decodedBytes = Base64.getDecoder().decode(encryptedPassword);

            // Perform the decryption
            byte[] decryptedBytes = cipher.doFinal(decodedBytes);

            // Convert the decrypted bytes to a string using UTF-8 encoding
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException |
                 InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException e) {
            // Handle any exception that occurs during decryption and rethrow it as a RuntimeException
            throw new RuntimeException("Decryption failed.", e);
        }
    }
}

