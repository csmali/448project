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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

//  Crypto
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.Arrays;
import java.util.Base64;
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

    private String roomKey = "";

    //    KeyManagerFactory keyManagerFactory;
//    TrustManagerFactory trustManagerFactory;
    //  ChatClient Constructor
    //
    //  empty, as you can see.
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
            String serverHost, int serverPort,
            String room) {

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

            String line = "";
            int randomX = 0;
            String finalHash = "";
            boolean connectionEstablished = false;
            int connectionStage = 0;
            String tempKey = "";
            while (!connectionEstablished) {

                //Eger random int gelmi�se
                if (connectionStage == 0 && (line = _in.readLine()) != null) {
                    System.out.println(line);

                    randomX = Integer.parseInt(line);
                    String str = String.valueOf(password);
                    for (int i = 0; i < 15; i++) {
                        str = CipherAct.sha1(str);
                    }
                    finalHash = CipherAct.sha1(CipherAct.xor(str, randomX + ""));
                    String encrypted = CipherAct.encryptWithPublic(finalHash + room);
                    System.out.println("" + encrypted);
                    tempKey = new String(encrypted);
                    System.out.println(encrypted.length() + "  tempkeylength");
                    connectionStage++;
                    _out.println(encrypted);
                } //Sifreli bir sekilde roomKey gelmi�se
                else if (connectionStage == 1 && (line = _in.readLine()) != null) {
                    System.out.println("DECRYPTION KEY" + finalHash.substring(0, 32));
                    roomKey = new String(CipherAct.decrypt(line, finalHash.substring(0, 32)));
                    System.out.println("roomKey" + roomKey);
                    connectionEstablished = true;
                    connectionStage = 0;
                }
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

            String encryptedMsg = CipherAct.encrypt(msg, roomKey);
            String encrypted = encryptedMsg;

            String hmac = CipherAct.calculateRFC2104HMAC((roomKey + CipherAct.calculateRFC2104HMAC(roomKey + encrypted, roomKey)), roomKey);

            encrypted = new String(encrypted) + hmac;
            System.out.println("msg" + msg);
            System.out.println("encrypted" + encrypted);

            _out.println(encrypted);

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

    public String getRoomKey() {
        return roomKey;
    }
}
