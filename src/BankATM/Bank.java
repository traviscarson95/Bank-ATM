package BankATM;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Hashtable;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.TimerTask;
import java.util.Timer;
import java.util.concurrent.TimeUnit;

public class Bank {
    private int port;
    private String authF;
    private SecureRandom rng;
    private byte[] bytes;
    private Hashtable<String, Account> accounts;
    private Hashtable<String, Integer> fails;
    private Hashtable<String, Boolean> retrans;
    private Timer t;


    // Creates a bank object with the user-provided port and authentication file.
    private Bank(int port, String authF) throws Exception{
        this.port = port;
        this.authF = authF;
        rng = new SecureRandom();
        bytes = new byte[8];
        accounts = new Hashtable<String, Account>();
        fails = new Hashtable<String, Integer>();
        retrans = new Hashtable<String, Boolean>();
        t = new Timer();
        generate_auth();
    }


    /*************************************** TRANSACTION CLASS ****************************************************/
    /**************** Transaction will communicate to the Bank class on behalf of the ATM class.*******************/
    private class Transaction extends Thread {
        private Bank bank;
        private Socket socket;
        private BufferedReader in;
        private PrintWriter out;
        private Long idNumber;

        // Creates a new Transaction.
        private Transaction(Bank bank, Socket socket) throws Exception {
            this.bank = bank;
            this.socket = socket;
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);
            String ip = socket.getRemoteSocketAddress().toString();
            if(fails.containsKey(ip) && fails.get(ip) >= 5)
                TimeUnit.SECONDS.sleep(10);
        }


        // Takes a command line input string, parses it, and launches the corresponding server response method
        private void switchboard(String input) throws Exception{

            String[] args = input.split(" ");

            //args[0] = transaction id number
            //args[1] = operation (CHECK_BALANCE, CREATE_ACCOUNT, DEPOSIT, WITHDRAW)
            //args[2] = cardF info (128 bit AES key)
            //args[3] = accountName
            //args[4] = amount (0 for CHECK_BALANCE)

            idNumber = Long.parseLong(args[0]);
            if (retrans.containsKey(args[0])){
                String ip = socket.getRemoteSocketAddress().toString();
                addFail(ip);
                out.println(encrypt("FAIL",bank.authF));
            }else{
                retrans.put(args[0], true);
            }


            if (args[1].equals("CHECK_BALANCE")){
                account_balance_query(args[2],args[3]);
            }else if (args[1].equals("CREATE_ACCOUNT")){
                new_account_query(args[2],args[3],args[4]);
            }else if (args[1].equals("DEPOSIT")){
                deposit_query(args[2],args[3],args[4]);
            }else if (args[1].equals("WITHDRAW")){
                withdraw_query(args[2],args[3],args[4]);
            }else{
                String ip = socket.getRemoteSocketAddress().toString();
                addFail(ip);
                out.println(encrypt("FAIL",bank.authF));
            }
        }


        //Server response method to CREATE_ACCOUNT
        private void new_account_query(String pin, String accountName, String amount) throws Exception{
            //VERIFY
            if(!verifyAccount(accountName,pin)){ //not in current table
                makeAccount(accountName, amount, pin);
                String res = "{\"account\":\""+accountName+"\",\"initial_balance\":"+amount+"}";
                bank.print(res);
                out.println(encrypt(res,bank.authF));
            } else { //user already in system
                String ip = socket.getRemoteSocketAddress().toString();
                addFail(ip);
                out.println(encrypt("FAIL",bank.authF));
            }
        }


        //Server response method to CHECK_BALANCE
        private void account_balance_query(String pin, String accountName) throws Exception{
            //VERIFY
            if(verifyAccount(accountName,pin)){  //currently table
                String balance = ((Account) bank.accounts.get(accountName)).getBalance();
                String res = "{\"account\":\""+accountName+"\",\"balance\":"+balance+"}";
                bank.print(res);
                out.println(encrypt(res,bank.authF));
            } else { //user not in system
                String ip = socket.getRemoteSocketAddress().toString();
                addFail(ip);
                out.println(encrypt("FAIL",bank.authF));
            }
        }


        //Server response method to DEPOSIT
        private void deposit_query(String pin, String accountName, String amount) throws Exception{
            //VERIFY
            if(verifyAccount(accountName,pin)){ //currently in table
                ((Account) bank.accounts.get(accountName)).deposit(amount);
                String res = "{\"account\":\""+accountName+"\",\"deposit\":"+amount+"}";
                bank.print(res);
                out.println(encrypt(res,bank.authF));
            } else { //user already in system
                String ip = socket.getRemoteSocketAddress().toString();
                addFail(ip);
                out.println(encrypt("FAIL",bank.authF));
            }
        }


        //Server response method to WITHDRAW
        private void withdraw_query(String pin, String accountName, String amount) throws Exception{
            //VERIFY
            if(verifyAccount(accountName,pin)){ //currently in table
                Account curr = bank.accounts.get(accountName);
                String balance = curr.getBalance();
                BigDecimal b = new BigDecimal(balance);
                BigDecimal a = new BigDecimal(amount);

                if((b.subtract(a)).compareTo(BigDecimal.ZERO) >= 0){
                    curr.withdraw(amount);
                    String res = "{\"account\":\""+accountName+"\",\"withdraw\":"+amount+"}";
                    bank.print(res);
                    out.println(encrypt(res,bank.authF));

                }
            } else { //user not in system or not enough money
                String ip = socket.getRemoteSocketAddress().toString();
                addFail(ip);
                out.println(encrypt("FAIL",bank.authF));
                throw new IOException();
            }
        }

        //Verifies than an account exists, and matches pins
        private boolean verifyAccount(String name, String pin) throws Exception{
            if (accounts.containsKey(name)){
                Account curr = accounts.get(name);
                if (curr.getPin().equals(pin)){
                    return true;
                }else{
                    out.println(encrypt("FAIL",bank.authF));
                    throw new IOException();
                }
            }
            return false;
        }


        // Handles commands sent by the ATM class. Called on transaction.start()
        public void run(){
            try {
                String input = decrypt(in.readLine(),bank.authF);
                switchboard(input);

            } catch (Exception e) {

            } finally {
                try {
                    out.println(encrypt("FAIL",bank.authF));
                    in.close();
                    out.close();
                    socket.close();
                } catch (Exception e) {
                }
            }
        }
    }


    /*************************************** ACCOUNT CLASS *********************************************************/
    /************************ Account will take commands from the Bank class ***************************************/
    private class Account{
        private String name, pin;
        private BigDecimal balance;

        // Create a new account with specified parameters.
        private Account(String name, String balance, String pin){
            this.name = name;
            this.balance = new BigDecimal(balance);
            this.pin = pin;
        }

        // Deposits money into the bank account; sum must be a String.
        private void deposit(String sum){
            balance = balance.add(new BigDecimal(sum));
        }

        // Withdraw money into the bank account; sum must be a String.
        private void withdraw(String sum){
            balance = balance.subtract(new BigDecimal(sum));
        }

        // Returns the balance of the account.
        private String getBalance(){
            return balance.toString();
        }



        // Returns the pin for use by the Bank.
        private String getPin(){
            return pin;
        }
    }


    /******************************************** MAIN *************************************************************/
    public static void main(String[] args) throws Exception {
        int clientNumber = 0;
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
        String [] res = parse_cmd_line(builder.toString());
        Bank bank = new Bank(Integer.parseInt(res[2]), res[1]);
        ServerSocket socket = bank.openSocket();
        Socket client = null;


        bank.t.scheduleAtFixedRate(new TimerTask(){
            public void run()
            {
                for(String ip: bank.fails.keySet()){
                    bank.fails.put(ip, 0);
                }
            }
        }, 0,      // run first occurrence immediately
        60000);    // run every 60 seconds

        try{
            while(true){
                try{
                    client = socket.accept();
                    bank.startTransaction(client);
                } catch (SocketException e){

                }
            }
        }
        finally{
            client.close();
        }
    }




    /***********************ENCRYPTION *****************************/
    // Encrypts the string value using the authentication file.
    private static String encrypt(String value, String authF) throws Exception {

        //READ AUTH FILE
        BufferedReader reader = new BufferedReader(new FileReader(authF));
        String key = reader.readLine();
        reader.close();

        SecretKeySpec skeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
        IvParameterSpec iv = new IvParameterSpec(skeySpec.getEncoded());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

        byte[] encrypted = cipher.doFinal(value.getBytes());

        return Base64.getEncoder().encodeToString(encrypted);
    }


    // Decrypts the string encrypted using the authentication file.
    private static String decrypt(String encrypted, String authF) throws Exception {
        //READ AUTH FILE
        BufferedReader reader = new BufferedReader(new FileReader(authF));
        String key = reader.readLine();
        reader.close();

        SecretKeySpec skeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), "AES");
        IvParameterSpec iv = new IvParameterSpec(skeySpec.getEncoded());

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);

        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encrypted));

        return new String(original);
    }


    /********************** NETWORKING ***************************/
    // Starts a new transaction with an ATM.
    private void startTransaction(Socket socket) throws Exception{
        Transaction transaction = new Transaction(this, socket);
        transaction.start();
    }


    //Opens the Server Socket for the client. Timeout after 30 seconds
    private ServerSocket openSocket() throws IOException, SocketException{
        ServerSocket socket = new ServerSocket(port);
        //socket.setSoTimeout(30000);
        return socket;
    }


    // Closes a Server Socket for the client.
    @SuppressWarnings("unused")
    private void closeSocket(ServerSocket socket) throws Exception{
        socket.close();
    }


    /********************* UTILITIES ******************************/
    // Creates the bank object with user-provided information from the command line.
    private static String[] parse_cmd_line(String input){
        String split[] = input.split(" -");
        String args[] = Arrays.copyOfRange(split,1,split.length);
        String res[] = new String[3];
        res[0] = "x";               //operation
        res[1] = "bank.auth";       //auth file
        res[2] = "3000";            //port
        boolean s = false;
        boolean p = false;
        for(int i =0;i < args.length; i++){
            if (args[i].length() > 0){
                char flag = args[i].charAt(0);
                if ('s' == flag && !s){    //auth-file
                    res[1] = args[i].substring(1,args[i].length()).trim();
                    verifyFileName(res[1]);
                    s = true;
                }  else if ('p' == flag && !p){    //port
                    res[2] = args[i].substring(1,args[i].length()).trim();
                    verifyPort(res[2]);
                    p = true;
                }  else {
                    System.err.println("INVALID BANK INPUT: PARSER");
                    System.exit(255);
                }
            }
        }

        return res;
    }


    // Generates the authentication file. The file cannot change after this method.
    private void generate_auth() throws Exception{
        File authExists = new File(authF);
        if(authExists.exists())
            System.exit(255);

        KeyGenerator kgen = KeyGenerator.getInstance("AES");
        kgen.init(128, rng);
        SecretKey aesKey = kgen.generateKey();
        byte[] encoded = aesKey.getEncoded();

        PrintWriter writer = new PrintWriter(authF, "UTF-8");
        writer.println(Base64.getEncoder().withoutPadding().encodeToString(encoded));
        writer.close();
        print("created");
    }


    //Adds an Account to the Bank.
    private void makeAccount(String name, String balance, String pin){
        Account newAccount = new Account(name, balance, pin);
        accounts.put(name, newAccount);
    }


    // Verifies the regular expression for a port number.
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


    // Verifies the regular expression for a file name.
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


    // Returns a secure 64-bit decimal number in long form.
    private long getRandom(){
        rng.nextBytes(bytes);
        return (new BigInteger(bytes)).longValue();
    }


    // Increases value in fails hash by 1
    private void addFail(String ip){
        if (!fails.containsKey(ip))
            fails.put(ip, 1);
        else
            fails.put(ip, fails.get(ip) + 1);
    }

    // Prints to STDOUT
    private void print(String message){
        System.out.println(message);
        System.out.flush();
    }

}
