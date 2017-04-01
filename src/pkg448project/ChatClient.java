//  ChatClient.java
//
//  Modified 1/30/2000 by Alan Frindell
//  Last modified 2/18/2003 by Ting Zhang 
//  Last modified : Priyank Patel <pkpatel@cs.stanford.edu>
//
//  Chat Client starter application.
package Chat;

//  AWT/Swing
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

//  Java
import java.io.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

//  Crypto
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.Arrays;
import java.util.Formatter;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.security.auth.x500.*;
import javax.xml.bind.DatatypeConverter;

public class ChatClient {

    public static final int SUCCESS = 0;
    public static final int CONNECTION_REFUSED = 1;
    public static final int BAD_HOST = 2;
    public static final int ERROR = 3;
    String _loginName;
    ChatServer _server;
    ChatClientThread _thread;
    ChatLoginPanel _loginPanel;
    ChatRoomPanel _chatPanel;
    PrintWriter _out = null;
    BufferedReader _in = null;
    CardLayout _layout;
    JFrame _appFrame;

    Socket _socket = null;
    SecureRandom secureRandom;
    KeyStore clientKeyStore;
    KeyStore caKeyStore;

    private static String salt;
    private static int iterations = 65536;
    private static int keySize = 256;
    private static byte[] ivBytes;
    private static SecretKey secretKey;
//    KeyManagerFactory keyManagerFactory;
//    TrustManagerFactory trustManagerFactory;
    //  ChatClient Constructor
    //
    //  empty, as you can see.
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();

        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }

    public static String calculateRFC2104HMAC(String data, String key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(signingKey);
        return toHexString(mac.doFinal(data.getBytes()));
    }

    public ChatClient() {

        _loginName = null;
        _server = null;

        try {
            initComponents();
        } catch (Exception e) {
            System.out.println("ChatClient error: " + e.getMessage());
            e.printStackTrace();
        }

        _layout.show(_appFrame.getContentPane(), "Login");

    }

    public void run() {
        _appFrame.pack();
        _appFrame.setVisible(true);

    }

    //  main
    //
    //  Construct the app inside a frame, in the center of the screen
    public static void main(String[] args) {

        ChatClient app = new ChatClient();

        app.run();
    }

    //  initComponents
    //
    //  Component initialization
    private void initComponents() throws Exception {

        _appFrame = new JFrame("CS255 Chat");
        _layout = new CardLayout();
        _appFrame.getContentPane().setLayout(_layout);
        _loginPanel = new ChatLoginPanel(this);
        _chatPanel = new ChatRoomPanel(this);
        _appFrame.getContentPane().add(_loginPanel, "Login");
        _appFrame.getContentPane().add(_chatPanel, "ChatRoom");
        _appFrame.addWindowListener(new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                quit();
            }
        });
    }

    //  quit
    //
    //  Called when the application is about to quit.
    public void quit() {

        try {
            _socket.shutdownOutput();
            _thread.join();
            _socket.close();

        } catch (Exception err) {
            System.out.println("ChatClient error: " + err.getMessage());
            err.printStackTrace();
        }

        System.exit(0);
    }

    //
    //  connect
    //
    //  Called from the login panel when the user clicks the "connect"
    //  button. You will need to modify this method to add certificate
    //  authentication.  
    //  There are two passwords : the keystorepassword is the password
    //  to access your private key on the file system
    //  The other is your authentication password on the CA.
    //
    public int connect(String loginName, char[] password,
            String keyStoreName, char[] keyStorePassword,
            String caHost, int caPort,
            String serverHost, int serverPort,String serverRoom) {

        try {

            _loginName = loginName;

            //
            //  Read the client keystore
            //         (for its private/public keys)
            //  Establish secure connection to the CA
            //  Send public key and get back certificate
            //  Use certificate to establish secure connection with server
            //
            _socket = new Socket(serverHost, serverPort);
            _out = new PrintWriter(_socket.getOutputStream(), true);

            _in = new BufferedReader(new InputStreamReader(
                    _socket.getInputStream()));
            _out.println("Hello" + loginName);
            String line;
            int randomX = 0;
            String randomX2String;
            boolean connectionEstablished = false;
            while (!connectionEstablished) {
                while ((line = _in.readLine()) != null) {
                    randomX = Integer.parseInt(line);
                    connectionEstablished = true;
                    break;
                }

                String str = String.valueOf(password);
                String finalHash = str;
                for (int i = 0; i < 15; i++) {
                    finalHash = sha1(finalHash);
                }
                randomX2String = randomX + "";

                Path path = Paths.get("serverPublicKey");
                byte[] getEncoded = Files.readAllBytes(path);
                _out.println(xor(finalHash, randomX2String));

           //     sign(xor(finalHash, randomX2String), getEncoded);

            }

            _layout.show(_appFrame.getContentPane(), "ChatRoom");

            _thread = new ChatClientThread(this);
            _thread.start();
            return SUCCESS;

        } catch (UnknownHostException e) {

            System.err.println("Don't know about the serverHost: " + serverHost);
            System.exit(1);

        } catch (IOException e) {

            System.err.println("Couldn't get I/O for "
                    + "the connection to the serverHost: " + serverHost);
            System.out.println("ChatClient error: " + e.getMessage());
            e.printStackTrace();

            System.exit(1);

        } catch (AccessControlException e) {

            return BAD_HOST;

        } catch (Exception e) {

            System.out.println("ChatClient err: " + e.getMessage());
            e.printStackTrace();
        }

        return ERROR;

    }

    //  sendMessage
    //
    //  Called from the ChatPanel when the user types a carrige return.
    public void sendMessage(String msg) {

        try {
            msg = msg.substring(0, msg.length() - 1);
            msg = _loginName + "> " + msg;
            salt = getSalt();

            char[] message = msg.toCharArray();
            String encryptedMessage = encrypt(message);
            String secretKeyString = "";

            try (BufferedReader br = new BufferedReader(new FileReader("secretKeyString.txt"))) {
                String line;
                while ((line = br.readLine()) != null) {
                    secretKeyString = line;
                }
            }
            System.out.println("Message: " + String.valueOf(message));
            System.out.println("Encrypted: " + encryptedMessage);
            String hmac = calculateRFC2104HMAC((secretKeyString + calculateRFC2104HMAC(secretKeyString + encryptedMessage, secretKeyString)), secretKeyString);

            msg = encryptedMessage + hmac;
            System.out.println(msg);

            _out.println(msg);

        } catch (Exception e) {

            System.out.println("ChatClient err: " + e.getMessage());
            e.printStackTrace();
        }

    }

    public Socket getSocket() {

        return _socket;
    }

    public JTextArea getOutputArea() {

        return _chatPanel.getOutputArea();
    }

    public static String getSalt() throws Exception {

        SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
        byte[] salt = new byte[20];
        sr.nextBytes(salt);
        return new String(salt);

    }

    public static String encrypt(char[] plaintext) throws Exception {
        byte[] saltBytes = salt.getBytes();

        SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
        PBEKeySpec spec = new PBEKeySpec(plaintext, saltBytes, iterations, keySize);
        secretKey = skf.generateSecret(spec);
        SecretKeySpec secretSpec = new SecretKeySpec(secretKey.getEncoded(), "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretSpec);
        AlgorithmParameters params = cipher.getParameters();
        ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(String.valueOf(plaintext).getBytes("UTF-8"));
        try (PrintWriter out = new PrintWriter("secretKeyString.txt")) {
            out.println(secretKey.getEncoded());
        }
        FileOutputStream fos = new FileOutputStream("ivbytes");
        fos.write(ivBytes);
        fos.close();
        fos = new FileOutputStream("secretKey");
        fos.write(secretKey.getEncoded());
        fos.close();
        return DatatypeConverter.printBase64Binary(encryptedTextBytes);
    }
/*
    public static String sign(char[] plaintext,byte[] array) throws Exception {

        SecretKeySpec secretSpec = new SecretKeySpec(array, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretSpec);
        AlgorithmParameters params = cipher.getParameters();
        ivBytes = params.getParameterSpec(IvParameterSpec.class).getIV();
        byte[] encryptedTextBytes = cipher.doFinal(String.valueOf(plaintext).getBytes("UTF-8"));
        try (PrintWriter out = new PrintWriter("secretKeyString.txt")) {
            out.println(secretKey.getEncoded());
        }
        FileOutputStream fos = new FileOutputStream("ivbytes");
    
        return DatatypeConverter.printBase64Binary(encryptedTextBytes);
    }*/

    public static String sha1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

    public static String xor(String s, String key) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            sb.append((char) (s.charAt(i) ^ key.charAt(i % key.length())));
        }
        String result = sb.toString();
        return result;
    }

}
