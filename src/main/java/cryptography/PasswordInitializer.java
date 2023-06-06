package cryptography;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Properties;
import java.util.Scanner;

public class PasswordInitializer {
    private static final String CONFIG_FILE = "src/main/java/cryptography/config.properties";

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);

        // Get password from the user
        System.out.print("Enter your password: ");
        String password = sanitizeInput(scanner.nextLine());

        // Perform input validation
        if (!isValidPassword(password)) {
            System.out.println("Invalid password. Password should have at least 8 characters and contain both letters and numbers.");
            scanner.close();
            return;
        }

        // Generate secret key and initialization vector
        SecretKey secretKey = CustomKeyGenerator.generateSecretKey();
        byte[] initializationVector = CustomKeyGenerator.generateInitializationVector();

        // Encrypt the password
        String encryptedPassword = PasswordEncryptor.encrypt(password, secretKey, initializationVector);

        // Store the encrypted password in the configuration file
        writePasswordToConfigFile(encryptedPassword, secretKey, initializationVector);

        // Clear the password from memory
        clearPassword(password);

        System.out.println("Password initialized successfully.");

        scanner.close();
    }

    // Sanitize user input to prevent any unwanted characters
    private static String sanitizeInput(String input) {
        return input.trim();
    }

    // Perform input validation for the password
    private static boolean isValidPassword(String password) {
        // Validate password criteria (at least 8 characters and contains both letters and numbers)
        String passwordPattern = "^(?=.*[A-Za-z])(?=.*\\d).{8,}$";
        return password.matches(passwordPattern);
    }

    private static void writePasswordToConfigFile(String encryptedPassword, SecretKey secretKey, byte[] initializationVector) {
        try {
            // Create the directory if it doesn't exist
            String directoryPath = CONFIG_FILE.substring(0, CONFIG_FILE.lastIndexOf('/'));
            Files.createDirectories(Paths.get(directoryPath));

            File configFile = new File(CONFIG_FILE);
            if (!configFile.exists()) {
                configFile.createNewFile();
            }

            try (FileOutputStream fileOutputStream = new FileOutputStream(configFile)) {
                Properties properties = new Properties();
                properties.setProperty("password", encryptedPassword);
                properties.setProperty("secretKey", Base64.getEncoder().encodeToString(secretKey.getEncoded()));
                properties.setProperty("initializationVector", Base64.getEncoder().encodeToString(initializationVector));
                properties.store(fileOutputStream, null);
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to write to the configuration file.", e);
        }
    }

    private static void clearPassword(String password) {
        // Clear the password by overwriting with zeros
        char[] passwordChars = password.toCharArray();
        for (int i = 0; i < passwordChars.length; i++) {
            passwordChars[i] = 0;
        }
    }
}
