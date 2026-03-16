/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package com.mycompany.passwordmanager;
import java.util.List;
import java.util.ArrayList;
import java.io.Serializable;
/**
 *
 * @author Zeina
 */
//Save to file,as bytes 
public class PasswordEntry implements Serializable {
    private static final long serialVersionUID = 1L;  //checks if saved version matches current version
     public String app;
    public String username;
    public byte[] encryptedPassword;

    public PasswordEntry(String app,String username,byte[] encryptedPassword){
        this.app=app; 
        this.username=username; 
        this.encryptedPassword=encryptedPassword;
    }
    
}
