package pkg448project;

//  AWT/Swing
import java.awt.*;
import java.awt.event.*;
import javax.swing.*;

//  Java
import java.io.*;

// socket
import java.net.*;

//  Crypto
import java.security.*;

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

        _appFrame = new JFrame("BIL448 Chat");
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

            //Server'a baglanmanin ilk adimi Hello mesaji gondermektir.
            //Bu mesajda client, Hello ve client name'i server'a gonderir.
            _out.println("Hello" + loginName);

            String line = "";
            int randomX = 0;
            boolean connectionEstablished = false;
            int connectionStage = 0;
            String tempKey = "";
            while (!connectionEstablished) {

                /*Eger server'dan beklenen random integer gelmisse
                 * Password ilgili islemlere sokulur. Ardina room Name eklenir ve server'a gonderilir.
                 * Gecici key belirlenir.
                 */
                if (connectionStage == 0 && (line = _in.readLine()) != null) {
                    randomX = Integer.parseInt(line);
                    if (randomX == 77777) {
                        _socket.close();
                        System.out.println("Unknown User Name");
                        return 77777;
                    }
                    String str = String.valueOf(password);
                    for (int i = 0; i < 15; i++) {
                        str = CipherAct.sha1(str);
                    }
                    tempKey = CipherAct.sha1(CipherAct.xor(str, randomX + ""));
                    String encrypted = CipherAct.encryptWithPublic(tempKey + room);

                    connectionStage++;
                    _out.println(encrypted);
                } /* Room anahtari gelmisse
                 * tempKey kullanilarak decrypt edilir.
                 * Ardindan connection saglanir ve loop sona erer.
                 */ else if (connectionStage == 1 && (line = _in.readLine()) != null) {
                    if (line.equals("88888")) {
                        _socket.close();
                        System.out.println("Wrong Password");
                        return 88888;
                    }
                    roomKey = new String(CipherAct.decrypt(line, tempKey.substring(0, 32)));

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

            //Client mesaj olarak kendi ismi + > karakteri + mesaji gonderir.
            msg = msg.substring(0, msg.length() - 1);
            msg = _loginName + "> " + msg;

            //Mesaj butun olarak oda anahtari ile sifrelenir.
            String encryptedMsg = CipherAct.encrypt(msg, roomKey);

            //Bu mesajin HMAC'i alinir. Ve mesaj + HMAC cifti olarak server'a iletilir.
            String hmac = CipherAct.calculateRFC2104HMAC((roomKey + CipherAct.calculateRFC2104HMAC(roomKey + encryptedMsg, roomKey)), roomKey);

            String encryptedWithHMAC = new String(encryptedMsg) + hmac;

            _out.println(encryptedWithHMAC);

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
