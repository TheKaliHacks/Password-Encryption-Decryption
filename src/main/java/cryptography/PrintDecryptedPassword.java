package cryptography;

public class PrintDecryptedPassword {
    public static void main(String[] args) {
        // Create an instance of InitiateCrypto class
        InitiateCrypto crypto = new InitiateCrypto();

        // Call the main method of InitiateCrypto to initialize the decrypted password
        crypto.main(args);

        // Retrieve the decrypted password from InitiateCrypto
        String decryptedPassword = crypto.getDecryptedPassword();

        // Print the decrypted password to the console
        System.out.println("Decrypted password: " + decryptedPassword);
    }
}
