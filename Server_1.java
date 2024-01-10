package kerberos;

import java.io.*;
import java.net.*;
import java.time.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Server_1 {
    
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
    public static final long TS_2 = System.currentTimeMillis()/1000;
    public static final long TS_4 = System.currentTimeMillis()/1000;
    
    //initialize lifetime 2 and lifetime 4
    public static final long lifetime_2 = 60, lifetime_4 = 86400;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    
    //declare key variables
    private static SecretKey KEY_C, KEY_C_TGS, KEY_TGS, KEY_V, KEY_C_V;
    
    public static void main(String srgs[]) throws IOException{
        Socket s = new Socket(SERVER_IP, SERVER_PORT); //establish socket connection with the server
        
        BufferedReader clientMsg = new BufferedReader(new InputStreamReader(s.getInputStream()));
        String recvMsg = clientMsg.readLine();
        System.out.println("Received message: " + recvMsg);
        
        Scanner get_key_c = new Scanner(new File("KEY_C.txt"));
        String read_key_c = get_key_c.next();
        
        Scanner get_key_tgs = new Scanner(new File("KEY_TGS.txt"));
        String read_key_tgs = get_key_tgs.next();
        
        //generate new key to share between client and TGS
        PrintStream key_c_tgs_file;
        String write_key_c_tgs = "";
        try{
            KEY_C_TGS = KeyGenerator.getInstance("DES").generateKey(); //call Key Generator method to construct DES key
            write_key_c_tgs = Base64.getEncoder().encodeToString(KEY_C_TGS.getEncoded()); //convert from secret key variable to string
            key_c_tgs_file = new PrintStream(new File("KEY_C_TGS.txt")); //make new text file to hold key string
            key_c_tgs_file.println(write_key_c_tgs); //print key to file
            
            byte []key1 = Base64.getDecoder().decode(read_key_c); //convert string to secret key variable
            KEY_C = new SecretKeySpec(key1, 0, key1.length, "DES"); //initialize secret key variable
            
            byte []key2 = Base64.getDecoder().decode(read_key_tgs); //convert string to secret key variable
            KEY_TGS = new SecretKeySpec(key2, 0, key2.length, "DES"); //initialize secret key variable
        }catch(Exception e){
            System.out.println(e);
        }
        
        String make_ticket = write_key_c_tgs.concat(ID_C.concat(AD_C.concat(ID_TGS.concat(String.valueOf(TS_2).concat(String.valueOf(lifetime_2)))))); //make concatenation
        String ticket_tgs = encryption(KEY_TGS, make_ticket); //initialize TGS ticket
        //System.out.println("Ticket (TGS) is: " + ticket_tgs); //print TGS ticket
        
        //get length of TGS ticket and place in shared file
        PrintStream ticket_tgs_len;
        try{
            ticket_tgs_len = new PrintStream(new File("ticket_tgs_len.txt")); //make new file
            int len = ticket_tgs.length(); //get legnth of TGS ticket
            ticket_tgs_len.println(len); //print length ni file
        }catch(Exception e){
            System.out.println(e);
        }
        
        String plaintext = write_key_c_tgs.concat(ID_TGS.concat(String.valueOf(TS_2)).concat(String.valueOf(lifetime_2).concat(ticket_tgs))); //make concatenation and set it equal to plaintext
        String ciphertext = encryption(KEY_C, plaintext); //encrypt plaintext using KEY_C
        //System.out.println("Cyphertext is: " + ciphertext); //print ciphertext
        
        //send ciphertext to client
        PrintWriter output = new PrintWriter(s.getOutputStream(), true);
        output.println(ciphertext);
        
        //read from client and print received ciphertext
        BufferedReader clientMsg2 = new BufferedReader(new InputStreamReader(s.getInputStream()));
        String recvCiphertext = clientMsg2.readLine();
        System.out.println();
        System.out.println("Received message: " + recvCiphertext);
        checkValidity(); //check validity of TGS tickets
                
        //read from shared KEY_V file
        Scanner get_key_v = new Scanner(new File("KEY_V.txt"));
        String read_key_v = get_key_v.next();
        
        //generate new key to share between client and TGS
        PrintStream key_c_v_file;
        String write_key_c_v = "";
        try{
            KEY_C_V = KeyGenerator.getInstance("DES").generateKey(); //call Key Generator method to construct DES key
            write_key_c_v = Base64.getEncoder().encodeToString(KEY_C_V.getEncoded()); //convert from secret key variable to string
            key_c_v_file = new PrintStream(new File("KEY_C_V.txt")); //make new text file to hold key string
            key_c_v_file.println(write_key_c_v); //print key to file
            
            byte []key1 = Base64.getDecoder().decode(read_key_v); //convert string to secret key variable
            KEY_V = new SecretKeySpec(key1, 0, key1.length, "DES"); //initialize secret key variable
        }catch(Exception e){
            System.out.println(e);
        }
        
        //make second concatenation
        String secConCat = write_key_c_v.concat(ID_C.concat(AD_C.concat(ID_V.concat(String.valueOf(TS_4).concat(String.valueOf(lifetime_4))))));
        
        String ticket_v = encryption(KEY_V, secConCat); //initialize ticket_v
        System.out.println();
        System.out.println("Ticket (V) is: " + ticket_v); //print ticket_v
        
        //get length of ticket_v and print to new file
        PrintStream ticket_v_len;
        try{
            ticket_v_len = new PrintStream(new File("ticket_v_len.txt")); //make new file
            int len = ticket_v.length(); //get length of ticket_v
            ticket_v_len.println(len); //print length in file
        }catch(Exception e){
            System.out.println(e);
        }
        
        //make third concatenation
        String trdConCat = write_key_c_v.concat(ID_V.concat(String.valueOf(TS_4).concat(ticket_v))); 
        //System.out.println("Sent plaintext: " + trdConCat);
        
        String sendCiphertext = encryption(KEY_C_TGS, trdConCat); //encrypt plaintext
        System.out.println("Sent ciphertext: " + sendCiphertext);
        output.println(sendCiphertext); //send ciphertext to client
        
        s.close(); //close Socket
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
    
    //method checks if the TGS ticket did not expire
    public static void checkValidity(){
        if((Instant.now().getEpochSecond() - TS_2) < lifetime_2)
            System.out.println("Ticket is valid.");
        else
            System.out.println("Ticket is not valid.");
    }
    
}
