package kerberos;

import java.io.*;
import java.net.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class Client {
    
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
    public static final long TS = System.currentTimeMillis()/1000;
    public static final long TS_3 = System.currentTimeMillis()/1000;
    
    //initialize lifetime 2 and lifetime 4
    public static final long lifetime_2 = 60, lifetime_4 = 86400;
    
    private static Cipher encrypt; //encryption cipher
    private static Cipher decrypt; //decryption cipher
    
    //declare key variables
    private static SecretKey KEY_C, KEY_TGS, KEY_V;
    
    private static SecretKey KEY_C_TGS, KEY_C_V;
    
    public static void main(String args[]) throws IOException{
        String write_key_c = "", write_key_tgs = "", write_key_v = ""; //write the keys into file
        PrintStream key_c_file, key_tgs_file, key_v_file; //make files to hold keys
        
        try{
            //initialize keys and print them in shared texted files
            
            KEY_C = KeyGenerator.getInstance("DES").generateKey(); //call Key Generator method to construct DES key
            write_key_c = Base64.getEncoder().encodeToString(KEY_C.getEncoded()); //convert from secret key variable to string
            key_c_file = new PrintStream(new File("KEY_C.txt")); //make new text file to hold key string
            key_c_file.println(write_key_c); //print key to file
            
            KEY_TGS = KeyGenerator.getInstance("DES").generateKey(); //call Key Generator method to construct DES key
            write_key_tgs = Base64.getEncoder().encodeToString(KEY_TGS.getEncoded()); //convert from secret key variable to string
            key_tgs_file = new PrintStream(new File("KEY_TGS.txt")); //make new text file to hold key string
            key_tgs_file.println(write_key_tgs); //print key to file
            
            KEY_V = KeyGenerator.getInstance("DES").generateKey(); //call Key Generator method to construct DES key
            write_key_v = Base64.getEncoder().encodeToString(KEY_V.getEncoded()); //convert from secret key variable to string
            key_v_file = new PrintStream(new File("KEY_V.txt")); //make new text file to hold key string
            key_v_file.println(write_key_v); //print key to file
            
        }catch(Exception e){
            System.out.println(e);
        }
        
        ServerSocket listener = new ServerSocket(SERVER_PORT, 2); //set up server socket
        
        System.out.println("[CLIENT] Waiting for server connection ...");
        Socket client = listener.accept(); //client is connected with server
        System.out.println("[CLIENT] Accept new connection from 127.0.0.1");
        PrintWriter output = new PrintWriter(client.getOutputStream(), true);
        
        String sentMsg = ID_C.concat(ID_TGS.concat(String.valueOf(TS))); //concatenate variable
        output.println(sentMsg); //send concatenation to AS i.e. Server_1
        
        //read ciphertext from AS i.e. Server_1
        BufferedReader AS_response = new BufferedReader(new InputStreamReader(client.getInputStream()));
        String read_AS_response = AS_response.readLine();
        
        //System.out.println("Ciphertext is: " + read_AS_response);
        
        //the ciphertext, in hex, must be converted to bytes
        byte[] recvText = DatatypeConverter.parseHexBinary(read_AS_response);
        
        String plaintext = decryption(KEY_C, recvText);
        
        int read_ticket_c_len;
        Scanner get_ticket_c_len;
        String get_ticket_c = "";
        
        try{
            get_ticket_c_len = new Scanner(new File("ticket_tgs_len.txt"));
            read_ticket_c_len = get_ticket_c_len.nextInt();
            
            get_ticket_c = plaintext.substring(plaintext.length()-(read_ticket_c_len), plaintext.length());
            System.out.println();
            System.out.println("Plaintext is: " + plaintext.substring(0, plaintext.length()-read_ticket_c_len));
            System.out.println("Ticket (TGS) is: " + get_ticket_c);
        }catch(Exception e){
            System.out.println(e);
        }
        
        //prepare message to send to TGS i.e. Server_1
        String secConCat = ID_C.concat(AD_C.concat(String.valueOf(TS_3))); //concatenate variable
        
        //initialize C_TGS key by reading from shared key file
        Scanner get_key_c_tgs; //to get file
        String read_key_c_tgs; //to read from files
        try{
            get_key_c_tgs = new Scanner(new File("KEY_C_TGS.txt")); //find file containing key
            read_key_c_tgs = get_key_c_tgs.next(); //read from file
            byte []key = Base64.getDecoder().decode(read_key_c_tgs); //convert string to secret key variable
            KEY_C_TGS = new SecretKeySpec(key, 0, key.length, "DES"); //initialize secret key variable
        }catch(Exception e){
            System.out.println(e);
        }
        
        String Authenticator = encryption(KEY_C_TGS, secConCat); //initialize Authenticator with C_TGS key and concatenation
        String message = ID_V.concat(get_ticket_c.concat(Authenticator)); //further concatenation
        output.println(message); //send concatenation to TGS i.e. Server_1
        
        //read ciphertext from TGS i.e. Server_1
        BufferedReader TGS_response = new BufferedReader(new InputStreamReader(client.getInputStream()));
        String read_TGS_response = TGS_response.readLine();
        
        //System.out.println("Received ciphertext is: " + read_TGS_response);
        
        //the ciphertext, in hex, must be converted to bytes
        byte[] recvText_2 = DatatypeConverter.parseHexBinary(read_TGS_response);
        String plaintext_2 = decryption(KEY_C_TGS, recvText_2);
        
        //to get length of ticket_v
        int read_ticket_v_len;
        Scanner get_ticket_v_len;
        String get_ticket_v = "";
        
        try{
            get_ticket_v_len = new Scanner(new File("ticket_v_len.txt")); //find file
            read_ticket_v_len = get_ticket_v_len.nextInt(); //read from file
            
            get_ticket_v = plaintext_2.substring(plaintext_2.length()-(read_ticket_v_len), plaintext_2.length()); //initialize ticket_v string variable
            System.out.println();
            System.out.println("Received plaintext is: " + plaintext_2.substring(0, plaintext_2.length()-read_ticket_v_len)); //print plaintext
            System.out.println("Ticket (V) is: " + get_ticket_v); //print ticket_v
        }catch(Exception e){
            System.out.println(e);
        }
        
        //establish another socket connection - (V) i.e. Server_2
        Socket client2 = listener.accept(); //client is connected with second server
        PrintWriter output2 = new PrintWriter(client2.getOutputStream(), true);

        String frthConCat = get_ticket_v.concat(Authenticator); //make fourth concatenation
        
        output2.println(frthConCat); //send concatenation to V i.e. Server_2
        
        //read ciphertext from V i.e. Server_1
        BufferedReader V_response = new BufferedReader(new InputStreamReader(client2.getInputStream()));
        String read_V_response = V_response.readLine();
        //System.out.println("Ciphertext is: " + read_V_response);
        
        //initialize C_V key by reading from shared key file
        Scanner get_key_c_v; //to get file
        String read_key_c_v; //to read from files
        try{
            get_key_c_v = new Scanner(new File("KEY_C_V.txt")); //find file containing key
            read_key_c_v = get_key_c_v.next(); //read from file
            byte []key = Base64.getDecoder().decode(read_key_c_v); //convert string to secret key variable
            KEY_C_V = new SecretKeySpec(key, 0, key.length, "DES"); //initialize secret key variable
        }catch(Exception e){
            System.out.println(e);
        }
        
        //the ciphertext, in hex, must be converted to bytes
        byte[] recvText2 = DatatypeConverter.parseHexBinary(read_V_response);
        
        String plaintext2 = decryption(KEY_C_V, recvText2); //decrypt message received from V i.e. Server_2
        
        System.out.println();
        System.out.println("Plaintext is: " + plaintext2); //print plaintext received from V i.e. Server_2
        
        listener.close(); //close ServerSocket
        client.close(); client2.close(); //close Socket
    }
    
    //decryption method
    public static String decryption(SecretKey key, byte enMsg[]){
        try{
            decrypt = Cipher.getInstance("DES/ECB/PKCS5Padding"); //have Cipher variable encrypt using DES algorithm
            decrypt.init(Cipher.DECRYPT_MODE, key); //initialized Cipher variable to encrypt mode with secret key as parameter
            byte []deMsg = decrypt.doFinal(enMsg); //ecrypt text
            String oriMsg = new String(deMsg);
            return oriMsg;
        }catch(Exception e){
            System.out.println();
        }
        return "";
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
}
