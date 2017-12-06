package BankATM;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.net.Socket;
import java.net.SocketException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Atm {
    private BufferedReader in;
    private PrintWriter out;
    private Socket socket;
    private String authF;
    private long idNumber;
    private SecureRandom rng;
    private byte[] bytes;

    // Create socket and set timeout to 30 seconds
    private Atm(String authF, String address, int port) throws SocketException, Exception {
        socket = new Socket(address, port);
        socket.setSoTimeout(30000);
        this.authF = authF;
        in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        out = new PrintWriter(socket.getOutputStream(), true);
        rng = new SecureRandom();
        bytes = new byte[8];
        idNumber = getRandom();
    }

    /******************************** MAIN ******************************************/

    public static void main(String[] args) throws Exception {
        StringBuilder builder = new StringBuilder();
        for (String str: args)
        {
            int b_l = builder.toString().length();
            int s_l = str.length();
            if(b_l + s_l < 4096){
                builder.append(' '+str);
            } else {
                System.exit(255);
            }
        }
        String parsed[] = parser(builder.toString());     //change to args for normal operation

        //PARSE COMMANDS
        String operation = parsed[0];
        String authF = parsed[1];
        String ipaddr = parsed[2];
        int port = Integer.parseInt(parsed[3]);
        String cardF = parsed[4];
        String account = parsed[5];
        BigDecimal amount = new BigDecimal(parsed[6]);

        //SEND CORRESPONDING MESSAGE TO BANK
        try{
            Atm client = new Atm(authF,ipaddr,port);
            if (operation.equals("n")){
                client.newAccount(cardF,account,amount);

            }else if (operation.equals("d")){
                client.deposit(cardF, account,amount);

            }else if (operation.equals("w")){
                client.withdraw(cardF,account,amount);

            }else if (operation.equals("g")){
                client.getBalance(cardF,account);

            } else {
                System.err.println("UNKNOWN ATM COMMAND: MAIN");
                System.exit(255);
            }
        } catch (SocketException e){
            System.exit(63);
        }


        System.exit(0);
    }

    /******************************** UTILITIES *************************************/
    private static String[] parser(String input){
        String split[] = input.split(" -");
        String args[] = Arrays.copyOfRange(split,1,split.length);
        String res[] = new String[7];
        res[0] = "x";               //operation
        res[1] = "bank.auth";       //auth file
        res[2] = "127.0.0.1";       //ip address
        res[3] = "3000";            //port
        res[4] = "";                //card file
        res[5] = "";                //account
        res[6] = "0.00";            //amount
        boolean a = false;
        boolean n = false;
        boolean d = false;
        boolean w = false;
        boolean g = false;
        boolean s = false;
        boolean ip = false;
        boolean p = false;
        boolean c = false;
        int numops = 0;

        for(int i =0;i < args.length; i++){
            if (args[i].length() > 0){
                char flag = args[i].charAt(0);
                if ('a' == flag && !a){         //account name
                    res[5] = args[i].substring(1,args[i].length()).trim();
                    verifyAccountName(res[5]);
                    a = true;
                } else if ('n' == flag && !n){    //new account balance
                    res[0] = "n";
                    res[6] = args[i].substring(1,args[i].length()).trim();
                    verifyAmount(res[6]);
                    numops++;
                    n = true;
                } else if ('d' == flag && !d){    //deposit
                    res[0] = "d";
                    res[6] = args[i].substring(1,args[i].length()).trim();
                    verifyAmount(res[6]);
                    numops++;
                    d = true;
                } else if ('w' == flag && !w){    //withdraw
                    res[0] = "w";
                    res[6] = args[i].substring(1,args[i].length()).trim();
                    verifyAmount(res[6]);
                    numops++;
                    w = true;
                } else if ('g' == flag && !g){    //get balance
                    res[0] = "g";
                    args[i] = args[i].replace("g", "");
                    i = i-1;
                    numops++;
                    g = true;
                } else if ('s' == flag && !s){  //auth-file
                    res[1] = args[i].substring(1,args[i].length()).trim();
                    verifyFileName(res[1]);
                    s = true;
                } else if ('i' == flag && !ip){ //ip address
                    res[2] = args[i].substring(1,args[i].length()).trim();
                    verifyIP(res[2]);
                    ip = true;
                } else if ('p' == flag && !p){  //port
                    res[3] = args[i].substring(1,args[i].length()).trim();
                    verifyPort(res[3]);
                    p = true;
                } else if ('c'== flag && !c){       //card-file
                    res[4] = args[i].substring(1,args[i].length()).trim();
                    verifyFileName(res[4]);
                    c = true;
                } else {
                    System.err.println("INVALID ATM INPUT: PARSER");
                    System.exit(255);
                }
            }
        }
        if (a && !c){
            res[4] = res[5]+".card";
        }
        if (numops > 1){
            System.exit(255);
        }
        return res;
    }

    private static void verifyAmount(String amount){
        String pattern = "0.[0-9]{2}|[1-9][0-9]*.[0-9]{2}";
        if (amount.matches(pattern)){
            BigDecimal a = new BigDecimal(amount);
            BigDecimal b = new BigDecimal("4294967295.99");
            if(a.compareTo(BigDecimal.ZERO) >= 0 && a.compareTo(b) <= 0){
                //AWESOME
            } else {
                System.exit(255);
            }
        }else {
            System.exit(255);
        }
    }

    private static void verifyPort(String port){
        if (port.matches("(0|[1-9][0-9]*)")){
            try{
                int p = Integer.parseInt(port);
                if(p >= 1024 && p <= 65535){
                  //AWESOME
                }else{
                    System.exit(255);
                }
            } catch (Exception e){
                System.exit(255);
            }
        }else{
            System.exit(255);
        }
    }


    private static void verifyIP(String ip){
        String[] bit32 = ip.split("[.]");

        if(bit32.length != 4)
            System.exit(255);

        for (int i = 0; i < bit32.length; i++){
            if (bit32[i].matches("(0|[1-9][0-9]*)")){
                try{
                    int p = Integer.parseInt(bit32[i]);
                    if(p >= 0 && p <= 255){
                      //AWESOME
                    }else{
                        System.exit(255);
                    }
                 } catch (Exception e){
                     System.exit(255);
                 }
            }else{
                System.exit(255);
            }
        }
    }

    private static void verifyFileName( String file){
        String pattern = "[0-9a-z]|[-]|[_]|[.]";
        char [] chars = file.toCharArray();
        int length = chars.length; //check 1-255
        if (length < 1 || length > 255 || file.equals(".") || file.equals("..")){
            System.exit(255);
        }
        String curr;
        for (int i = 0; i < length; i++){
            curr = Character.toString(chars[i]);
            if(!curr.matches(pattern)){
                System.exit(255);
            }
        }
    }

    private static void verifyAccountName( String name){
        String pattern = "[0-9a-z]|[-]|[_]|[.]";
        char [] chars = name.toCharArray();
        int length = chars.length; //check 1-255
        if (length < 1 || length > 250){
            System.exit(255);
        }
        String curr;
        for (int i = 0; i < length; i++){
            curr = Character.toString(chars[i]);
            if(!curr.matches(pattern)){
                System.exit(255);
            }
        }
    }


    private static String getKey(String authF) throws IOException{
        //READ AUTH FILE
        BufferedReader reader = new BufferedReader(new FileReader(authF));
        String key = reader.readLine();
        reader.close();
        return key;
    }

    private String generate_card(String cardF) throws NoSuchAlgorithmException, FileNotFoundException, UnsupportedEncodingException{
        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128);
        SecretKey aesKey = kgen.generateKey();
        byte[] encoded = aesKey.getEncoded();
        PrintWriter writer = new PrintWriter(cardF, "UTF-8");
        String key = Base64.getEncoder().withoutPadding().encodeToString(encoded);
        writer.println(key);
        writer.close();
        return key;
    }

    /******************************* ENCRYPTION *************************************/

    private static String encrypt(String value, String authF) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(Base64.getDecoder().decode(getKey(authF)), "AES");
        IvParameterSpec iv = new IvParameterSpec(skeySpec.getEncoded());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(value.getBytes());

        return Base64.getEncoder().encodeToString(encrypted);
    }

    private static String decrypt(String encrypted, String authF) throws Exception {
        SecretKeySpec skeySpec = new SecretKeySpec(Base64.getDecoder().decode(getKey(authF)), "AES");
        IvParameterSpec iv = new IvParameterSpec(skeySpec.getEncoded());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

        return new String(original);
    }

    /******************************* MESSAGING **************************************/

    private void send(String message) throws Exception {
        out.println(encrypt(message,authF));
    }

    private String recieve(){
        try {
            String message =  decrypt(in.readLine(),authF);
            if (message.equals("FAIL")){
                System.exit(255);
            }else {
                return message;
            }
        } catch (Exception e) {
            System.exit(63);
        }
        return null;
    }

    private void newAccount(String cardF, String accountName, BigDecimal amount) throws Exception {
        //CHECK FOR CARDFILE
        if (!(new File(cardF).isFile()) && amount.compareTo(BigDecimal.TEN) >= 0){

            String info = generate_card(cardF);

            send(String.valueOf(idNumber) + " CREATE_ACCOUNT "+info+" "+accountName+" "+amount);
            info = null;
            System.out.println(recieve());
            System.out.flush();
            socket.close();

            //ACCOUNT EXISTS
        } else {
            System.err.println("CARD ALREADY EXISTS: NEW ACCOUNT");
            System.exit(255);
        }
    }

    private void getBalance(String cardF, String accountName) throws Exception{
        //CHECK FOR CARDFILE
        if (new File(cardF).isFile()){

            BufferedReader reader = new BufferedReader(new FileReader(cardF));
            String info = reader.readLine();
            reader.close();
            send(String.valueOf(idNumber) + " CHECK_BALANCE "+info+" "+accountName+" 0");
            info = null;
            System.out.println(recieve());
            System.out.flush();
            socket.close();

            //ACCOUNT EXISTS
        } else {
            System.err.println("NO CARD FOUND: CHECK BALANCE");
            System.exit(255);
        }
    }

    private void withdraw(String cardF, String accountName, BigDecimal amount)throws Exception {
        //CHECK FOR CARDFILE
        if (new File(cardF).isFile() && amount.compareTo(BigDecimal.ZERO) > 0){

            BufferedReader reader = new BufferedReader(new FileReader(cardF));
            String info = reader.readLine();
            reader.close();

            send(String.valueOf(idNumber) + " WITHDRAW "+info+" "+accountName+" "+amount);
            info = null;
            System.out.println(recieve());
            System.out.flush();
            socket.close();

            //ACCOUNT EXISTS
        } else {
            System.err.println("NO CARD FOUND: WITHDRAW");
            System.exit(255);
        }
    }

    private void deposit(String cardF, String accountName, BigDecimal amount) throws Exception {
        //CHECK FOR CARDFILE
        if (new File(cardF).isFile() && amount.compareTo(BigDecimal.ZERO) > 0){

            BufferedReader reader = new BufferedReader(new FileReader(cardF));
            String info = reader.readLine();
            reader.close();
            send(String.valueOf(idNumber) + " DEPOSIT "+info+" "+accountName+" "+amount);
            info = null;
            System.out.println(recieve());
            System.out.flush();
            socket.close();

            //ACCOUNT EXISTS
        } else {
            System.err.println("NO CARD FOUND: DEPOSIT");
            System.exit(255);
        }
    }


    // Returns a secure 64-bit decimal number in long form.
    private long getRandom(){
        rng.nextBytes(bytes);
        return (new BigInteger(bytes)).longValue();
    }

}
