/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package com.mycompany.passwordmanager;
import java.util.*;
import java.util.Scanner;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.ArrayList;
import java.io.*;
import java.nio.file.*;
import java.util.Base64;
/**
 *
 * @author Zeina
 */
public class PasswordManager {

   
    private static List<PasswordEntry> entries=new ArrayList<>();  
    private static Scanner sc=new Scanner(System.in);
      private static byte[] masterKey = null;
    private static boolean isFirstTime = true; // Assume first time until password is set
    private static final String CONFIG_FILE = "pm_config.dat";
    private static final String DATA_FILE = "pm_data.dat";
    
    public static void main(String[] args){
       
        loadConfig();
        
        if (isFirstTime) {
            setupMasterPassword();
        } else {
            login();
        }
        loadEntries();
        while(true){
            System.out.println("\n1-Add 2-View 3-Delete 4-Update 5-Change Password 6-Exit");
            String choice=sc.nextLine();
            switch(choice){
                case "1": addEntry(); saveEntries(); break;
                case "2": viewEntries(); break;
                case "3": deleteEntry(); saveEntries(); break;
                case "4": updateEntry(); saveEntries(); break;
                case "5": changeMasterPassword(); break;
                case "6": System.exit(0);
                default: System.out.println("Invalid"); break;
            }
        }
        
    }
       //Reads pm_config.dat file to check if the user have setup before.
      private static void loadConfig() {
        try {
            File configFile = new File(CONFIG_FILE);
            if (configFile.exists()) {
                BufferedReader reader = new BufferedReader(new FileReader(CONFIG_FILE));
                String keyBase64 = reader.readLine();
                reader.close();
                
                if (keyBase64 != null && !keyBase64.isEmpty()) {
                    masterKey = Base64.getDecoder().decode(keyBase64);
                    isFirstTime = false;
                }
            }
        } catch (IOException e) {
            System.out.println("Note: Starting fresh (no previous configuration found)");
        }
      }
      //Saves master key to pm_config.dat.
         private static void saveConfig() {
        try {
            PrintWriter writer = new PrintWriter(new FileWriter(CONFIG_FILE));
            String keyBase64 = Base64.getEncoder().encodeToString(masterKey);
            writer.println(keyBase64);
            writer.close();
        } catch (IOException e) {
            System.out.println("Warning: Could not save configuration");
        }
    }
    //Reads pm_data.dat to load the saved passwords.
    private static void loadEntries() {
        try {
            File dataFile = new File(DATA_FILE);
            if (dataFile.exists()) {
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(DATA_FILE));
                entries = (List<PasswordEntry>) ois.readObject();
                ois.close();
            }
        } catch (IOException | ClassNotFoundException e) {
            System.out.println("Note: No previous password entries found");
        }
    }
       //Saves all password entries to pm_data.dat.
       private static void saveEntries() {
        try {
            ObjectOutputStream oos = new ObjectOutputStream(new FileOutputStream(DATA_FILE));
            oos.writeObject(entries);
            oos.close();
        } catch (IOException e) {
            System.out.println("Warning: Could not save password entries");
        }
    }
       
        private static void setupMasterPassword() {
        System.out.println("\n=== First Time Setup ===");
        System.out.println("Welcome! You need to set a master password.");
        
        while (true) {
            System.out.print("Create master password: ");
            String password1 = sc.nextLine();
            
            System.out.print("Confirm master password: ");
            String password2 = sc.nextLine();
            
            if (password1.equals(password2)) {
                if (password1.length() < 4) {
                    System.out.println("Password must be at least 4 characters long!");
                } else {
                    // Set the master key
                    masterKey = deriveKey(password1);
                    isFirstTime = false;
                    System.out.println("Master password set successfully!");
                    System.out.println("You are now logged in.");
                    saveConfig();  //Saving the Master key
                    break;
                }
            } else {
                System.out.println("Passwords don't match! Try again.");
            }
        }
    }
    private static void login() {
        System.out.println("\n=== Login ===");
        
        int attempts = 0;
        while (attempts < 3) {
            System.out.print("Enter master password: ");
            String password = sc.nextLine();
            
            byte[] enteredKey = deriveKey(password);
            
            // If we have a stored masterKey, compare it
            if (masterKey == null || java.util.Arrays.equals(enteredKey, masterKey)) {
                masterKey = enteredKey;
                System.out.println("Login successful!");
                return;
            } else {
                attempts++;
                System.out.println("Incorrect password! Attempts left: " + (3 - attempts));
            }
        }
        
        System.out.println("Too many failed attempts. Exiting.");
        System.exit(0);
    }
    
    private static byte[] deriveKey(String password) {
        // Simple key derivation - pad to 16 bytes
        return Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8), 16);
    }
    
     private static void addEntry(){
      
        System.out.print("App: "); String app=sc.nextLine();
        System.out.print("Username: "); String username=sc.nextLine();
        System.out.print("Password: "); String password=sc.nextLine();
        System.out.println("Master key length: " + masterKey.length);
        byte[] pass16=Arrays.copyOf(password.getBytes(StandardCharsets.UTF_8),16);
        byte[] encrypted=AES.encryptBlock(pass16,masterKey,false);
        entries.add(new PasswordEntry(app,username,encrypted));
        System.out.println("Added!");
    }

    private static void viewEntries(){
        
        for(PasswordEntry e:entries){
            byte[] decrypted=AES.decryptBlock(e.encryptedPassword,masterKey,false);
            System.out.println("App:"+e.app+" Username:"+e.username+" Password:"+new String(decrypted).trim());
        }
    }
      private static void deleteEntry(){
        System.out.print("App to delete: "); String s=sc.nextLine();
        entries.removeIf(e->e.app.equalsIgnoreCase(s));
        System.out.println("Deleted!");
    }

    private static void updateEntry(){
        
        System.out.print("App to update: ");
        String s=sc.nextLine();
        for(PasswordEntry e:entries){
            if(e.app.equalsIgnoreCase(s)){
                System.out.print("New password: "); 
                String p=sc.nextLine();
                byte[] pass16=Arrays.copyOf(p.getBytes(StandardCharsets.UTF_8),16);
                e.encryptedPassword=AES.encryptBlock(pass16,masterKey,false);
                System.out.println("Updated!");
                return;
            }
        }
        System.out.println(" App not found!");
    }

    
    private static void changeMasterPassword() {
        System.out.println("\n=== Change Master Password ===");
        
        // Verify current password
        System.out.print("Enter current master password: ");
        String currentPassword = sc.nextLine();
        byte[] currentKey = deriveKey(currentPassword);
        
        if (!java.util.Arrays.equals(currentKey, masterKey)) {
            System.out.println("Incorrect current password!");
            return;
        }
        
        // Get new password
        System.out.print("Enter new master password: ");
        String newPassword1 = sc.nextLine();
        
        System.out.print("Confirm new master password: ");
        String newPassword2 = sc.nextLine();
        
        if (!newPassword1.equals(newPassword2)) {
            System.out.println("Passwords don't match!");
            return;
        }
        
        if (newPassword1.length() < 4) {
            System.out.println("Password must be at least 4 characters long!");
            return;
        }
        
        // Re-encrypt all existing entries with new key
        byte[] newMasterKey = deriveKey(newPassword1);
        
        for (PasswordEntry entry : entries) {
            // Decrypt with old key
            byte[] decrypted = AES.decryptBlock(entry.encryptedPassword, masterKey, false);
            // Re-encrypt with new key
            entry.encryptedPassword = AES.encryptBlock(decrypted, newMasterKey, false);
        }
        
        // Update master key
        masterKey = newMasterKey;
        System.out.println("Master password changed successfully!");
        saveConfig();    // Save new master key
        saveEntries();   // Save re-encrypted entries
    }
}




 
   

    


           
        
    


    

