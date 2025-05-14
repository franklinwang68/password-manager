import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import java.util.*;

import java.io.*;
import java.nio.file.Files;

/**
 * This class is a password manager.
 * It uses a salt to generate passwords with various other parameters
 * 
 * Security Risks:
 * If the saltString is copied from the file and used as a label
 * If non-alphanumeric characters are used for labels
 * The password file is not protected against changes or movement
 * Duplicate password files
 * If the password is meant to be an exception or error, the user may be confused
 */
public class PasswordManager {
    private static Scanner scanner; //scanner for inputs
    
    /**
     * Main
     * Checks if a password file exists. If it does, verifies the correct token is entered.
     * If password file does not exists, call createInitialPassword 
     * @param args
     */
    public static void main(String[] args) {
        scanner = new Scanner(System.in);
        
        //if password file exists
        try (BufferedReader reader = new BufferedReader(new FileReader("secretPass.txt"))) {
            //ask user for password
            System.out.println("Please Enter Your Password");
            String input = scanner.nextLine();

            //fetches salt
            String line = reader.readLine();
            String[] saltPass = parseLine(line);
            byte[] salt = Base64.getDecoder().decode(saltPass[0].getBytes());

            //generates key from input
            SecretKeySpec key = generateKey(input, salt);

            //attempts to decrypt stored token
            String password = decrypt(saltPass[1], key);

            //verify password with token and salt on file
            //The if statement should redundant. If the password is able to be decrypted, it should match
            if (password.equals(input)){
                cmdInterface(key);
            }
            else System.err.println("This should be unreachable");

        } 
        //if password file does not exist
        catch (FileNotFoundException e) {
            createInitialPassword();
        } 
        catch (Exception e2){
            System.err.println("Wrong Password Probably.");
        }
        scanner.close();
    }

    /**
     * Adds a password to the end of the file 
     * If label already exists, replace the password
     * @param key the key to encrypt passwords
     */
    private static void addPassword(SecretKeySpec key){
        System.out.println("Enter label: ");
        String label = scanner.nextLine();

        System.out.println("Enter password: ");
        String password = scanner.nextLine();

        try {
            File file = new File("secretPass.txt");
            File temp = new File("_temp_");
            PrintWriter out = new PrintWriter(new FileWriter(temp));

            //Checks if the label already exists
            Files.lines(file.toPath()) //get Stream<String>
                .filter(line -> !line.contains(label)) //filters the line with label if exists
                .forEach(out::println); //writes each line to file

            //appends the added password to the end of the file
            String encryptedPassword = encrypt(password, key);
            out.write(label + ":" + encryptedPassword + "\n");

            out.flush();
            out.close();

            temp.renameTo(file); //replace the old file with the new one

        } catch (Exception e) {
            System.err.println(e);
             System.exit(1);
        }
    }

    /**
     * Prints a password given a label
     * @param key the key to decrypt passwords
     */
    private static void readPassword(SecretKeySpec key){
        System.out.print("Enter label: ");
        String label = scanner.nextLine();

        //Read file for label
        try (BufferedReader reader = new BufferedReader(new FileReader("secretPass.txt"))) {
            String line;
            //for each line
            while ((line = reader.readLine()) != null) {
                //if label found 
                if(label.equals(parseLine(line)[0])){
                    String encodedPass = parseLine(line)[1];
                    String password = decrypt(encodedPass, key);
                    System.out.println(password);
                    return;
                }
            }
            System.err.println("javax.me.password.manager.NoSuchLabelException: The given label does not exist on file.");
        } catch (Exception e) {
            System.err.println(e);
        } 
    }

    /**
     * Encrypts a password with AES
     * @param password The String to encrypt
     * @param key the key to encrypt the String
     * @return The encrypted password
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    private static String encrypt(String password, SecretKeySpec key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
        //initializes the cipher
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);

        //encrypts the input string
        byte[] encryptedData = cipher.doFinal(password.getBytes());

        //encodes the encytped data
        String encodedData = new String(Base64.getEncoder().encode(encryptedData));

        return encodedData;
    }

    /**
     * Decodes the encytped data into a string.
     * Uses AES
     * @param encodedMessage the String to decrypt
     * @param key the key to decrypt the message
     * @return The decrypted message 
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     */
    private static String decrypt(String encodedMessage, SecretKeySpec key) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException{
        //initializes the cipher
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);

        //decodes the encodedMessage
        byte[] encryptedData = Base64.getDecoder().decode(encodedMessage);

        //decrypts the message
        byte[] decryptedData = cipher.doFinal(encryptedData);

        //converts the decrypted data into a String
        String decryptedMessage = new String(decryptedData);

        return decryptedMessage;
    }

    /**
     * cmd Interface
     * Activates the command interface to add or read a password
     * @param key
     */
    private static void cmdInterface(SecretKeySpec key){
        String option = "";

        while(!option.equals("q")){
            System.out.println("Choose option:\na : add password\nr : read password\nq : quit");
            option = scanner.nextLine();
            switch (option){
                case "a":
                    addPassword(key);
                    break;
                case "r":
                    readPassword(key);
                    break;
                case "q":
                    System.exit(0);
                default:
                    System.out.println("Invalid option");
                    break;
            }
        }
    }

    /**
     * Parses a line from the password file 
     * The part before ":" is in the 0th index and the part after ":" is in the 1st index
     * Assumes the line contains only one ":" and regular characters around it
     * @param line The line to parse
     * @return A String Array of size 2. Index 0 has the first part, index 1 has the second part
     */
    private static String[] parseLine(String line){
        return line.split(":");
    }

    /**
     * Generates a key from a given keyString and salt
     * Uses iteration 1024, keyLength 128, PBKDF2, SHA256, and AES 
     * @param keyString the password
     * @param salt the salt
     * @return the generated SecretKeySpec
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     */
    private static SecretKeySpec generateKey(String keyString, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException{
        KeySpec spec = new PBEKeySpec(keyString.toCharArray(), salt, 1024, 128);
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        SecretKey privateKey = factory.generateSecret(spec);
        SecretKeySpec key = new SecretKeySpec(privateKey.getEncoded(), "AES");

        return key;
    }

    /**
     * Creates the initial password file
     */
    private static void createInitialPassword(){
        //generate salt
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);
        String saltString = new String(Base64.getEncoder().encode(salt));

        //asks user to generate initial password
        System.out.print("Please create an initial password: ");
        String keyString = scanner.nextLine();

        //generate key, encrypt key, and write salt and encrypted key to file
        try(BufferedWriter writer = new BufferedWriter(new FileWriter("secretPass.txt"))){

            //generate key
            SecretKeySpec key = generateKey(keyString, salt);

            //encrypt key
            String encryptedKey = encrypt(keyString, key);

            //write to file
            writer.write(saltString + ":" + encryptedKey + "\n");

        } catch(Exception e){
            System.err.println(e);
        }
    }

}
