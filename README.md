# Password-Encryption-Decryption Cryptography Utility


Description:
This project provides a utility for encrypting and decrypting passwords using AES encryption. It includes several Java classes that enable secure password management.

Table of Contents:
1. Introduction
2. Features
3. Installation
4. Getting Started
5. Usage Examples
6. Dependencies
7. Contributing
8. License

1. Introduction:
   The Cryptography Utility is a Java-based utility designed to provide a simple and secure way to encrypt and decrypt passwords using AES encryption algorithm. It offers a set of features that facilitate secure password management.

2. Features:
- Password encryption using AES encryption algorithm
- Secure storage of encrypted passwords
- Key generation and management
- Initialization vector (IV) generation
- Command-line interface for password initialization using the PasswordInitializer class

3. Installation:
   To use this utility, follow these steps:
- Clone the project repository: https://github.com/anonpwnda/PasswordEncryptionDecryption.git
- Ensure you have Java 8 installed
- If using encryption with Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files, install the policy files for unlimited encryption strength

4. Getting Started:
   To start using the Cryptography Utility in your project, follow these steps:
- Import the required classes into your Java project
- Generate a secret key using the CustomKeyGenerator class
- Generate an initialization vector (IV) using the CustomKeyGenerator class

5. Usage Examples:
   a) Encrypting a Password:
   String encryptedPassword = PasswordEncryptor.encrypt(password, secretKey, initializationVector);

   b) Decrypting a Password:
   String decryptedPassword = PasswordDecryptor.decrypt(encryptedPassword, secretKey, initializationVector);

   c) Initializing Password:
   Run the PasswordInitializer class to initialize the password. The encrypted password will be stored in the configuration file.

6. Dependencies:
   This project has the following dependencies:
- Java Cryptography Extension (JCE) Unlimited Strength Jurisdiction Policy Files (if using unlimited encryption strength)

7. Contributing:
   Contributions are welcome! If you would like to contribute to this project, please follow these guidelines:
- Fork the repository and create a new branch
- Make your changes and test them thoroughly
- Create a pull request explaining the changes you made
- Please ensure the code passes all tests and follows the project's coding conventions

8. License:
   This project is licensed under the MIT License. For more details, please refer to the [LICENSE.md](https://github.com/anonpwnda/PasswordEncryptionDecryption/blob/main/src/main/java/cryptography/LICENSE.md) file.

For any questions or support, please contact me at ping@wajahatali.ca for any questions you might have.

