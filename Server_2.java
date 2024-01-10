package kerberos;

import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import java.time.*;
import javax.xml.bind.DatatypeConverter;

public class Server_2 {
    
    //two variables needed for socket programming
    public static final String SERVER_IP = "localhost";
    public static final int SERVER_PORT = 9001;
    
    //initialize strings that carry IDs
    public static final String ID_C = "CIS3319USERID";
    public static final String ID_V = "CIS3319SERVERID";
    public static final String ID_TGS = "CIS3319TGSID";
    
    //network address of client
    public static final String AD_C = "127.0.0.1:"+SERVER_PORT;
    
    //initialize epoch time
    public static final long TS_5 = System.currentTimeMillis()/1000;
    
    //initialize lifetime 2 and lifetime 4
    public static final long lifetime_2 = 60, lifetime_4 = 86400;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    
    //declare key variables
    private static SecretKey KEY_C, KEY_TGS, KEY_V, KEY_C_V;
        
    public static void main(String srgs[]) throws IOException{
        Socket s = new Socket(SERVER_IP, SERVER_PORT); //establish socket connection with the server
        
        BufferedReader clientMsg = new BufferedReader(new InputStreamReader(s.getInputStream()));
        String recvMsg = clientMsg.readLine();
        System.out.println("Received message: " + recvMsg);
        checkValidity(); //check validity of TGS tickets
        
        //generate new key to share between client and TGS
        PrintStream key_c_v_file;
        String write_key_c_v = "";
        try{
            KEY_C_V = KeyGenerator.getInstance("DES").generateKey(); //call Key Generator method to construct DES key
            write_key_c_v = Base64.getEncoder().encodeToString(KEY_C_V.getEncoded()); //convert from secret key variable to string
            key_c_v_file = new PrintStream(new File("KEY_C_V.txt")); //make new text file to hold key string
            key_c_v_file.println(write_key_c_v); //print key to file
        }catch(Exception e){
            System.out.println(e);
        }
        
        //print plaintext and ciphertext
        System.out.println("Plaintext is: " + String.valueOf(TS_5 + 1));
        System.out.println("Ciphertext is: " + encryption(KEY_C_V, String.valueOf(TS_5 + 1)));
        PrintWriter output = new PrintWriter(s.getOutputStream(), true);
        output.println(encryption(KEY_C_V, String.valueOf(TS_5 + 1))); //send ciphertext to client
        
        s.close(); //close socket
    }
    
    //encryption method
    public static String encryption(SecretKey key, String combinedText){        
        try{
            //Ecrypt concatenaetd string using DES
            encrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //have Cipher variable encrypt using DES algorithm
            encrypt.init(Cipher.ENCRYPT_MODE, key); //initialized Cipher variable to encrypt mode with secret key as parameter
            byte []text = combinedText.getBytes();
            byte []ciphertext = encrypt.doFinal(text); //ecrypt text
            //System.out.println("Cyphertext is: " + DatatypeConverter.printHexBinary(ciphertext)); //convert from bytes to Hex format
            return DatatypeConverter.printHexBinary(ciphertext);
        }catch(Exception e){
            System.out.println(e);
        }
        return "";
    }
    
    //method checks if the V ticket did not expired
    public static void checkValidity(){
        if((Instant.now().getEpochSecond() - TS_5) < lifetime_4)
            System.out.println("Ticket is valid.");
        else
            System.out.println("Ticket is not valid.");
    }
}
