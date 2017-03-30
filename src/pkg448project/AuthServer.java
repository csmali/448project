//
//  AuthServer.java
//
//  Written by : Priyank Patel <pkpatel@cs.stanford.edu>
//
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

//  Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

public class AuthServer {
    
    //  Failure codes
    public static final int SUCCESS = 0;
    public static final int KEYSTORE_FILE_NOT_FOUND = 1;
//    public static final int PERMISSIONS_FILE_NOT_FOUND = 2;
//    public static final int PERMISSIONS_FILE_TAMPERED = 3;
    public static final int ERROR = 4;
    //  The GUI
    AuthServerLoginPanel _panel;
    AuthServerActivityPanel _activityPanel;
    CardLayout _layout;
    JFrame _appFrame;
    AuthServerThread _thread;
    //  Port number to listen on
    private int _portNum;

    //  Data structures to hold the authentication
    //  information read from the file
    //  ............
    //  ............
    public AuthServer() throws Exception {

        _panel = null;
        _activityPanel = null;
        _layout = null;
        _appFrame = null;

        try {
            initialize();
        } catch (Exception e) {
            System.out.println("AS error: " + e.getMessage());
            e.printStackTrace();
        }

        _layout.show(_appFrame.getContentPane(), "ASPanel");

    }

    //  initialize
    //  
    //  AS initialization
    private void initialize() throws Exception {

        _appFrame = new JFrame("Authentication Server");
        _layout = new CardLayout();

        _appFrame.getContentPane().setLayout(_layout);
        _panel = new AuthServerLoginPanel(this);
        _appFrame.getContentPane().add(_panel, "ASPanel");

        _activityPanel = new AuthServerActivityPanel(this);
        _appFrame.getContentPane().add(_activityPanel, "ActivityPanel");

        _appFrame.addWindowListener(new WindowAdapter() {

            public void windowClosing(WindowEvent e) {
                quit();
            }
        });
    }

    public void run() {
        _appFrame.pack();
        _appFrame.setVisible(true);
    }

    //  quit
    //
    //  Called when the application is about to quit.
    public void quit() {

        try {
            System.out.println("quit called");
        } catch (Exception err) {
            System.out.println("AuthServer error: " + err.getMessage());
            err.printStackTrace();
        }

        System.exit(0);
    }

    //
    //  Start up the AS server
    //
    public int startup(String _ksFileName, char[] _privateKeyPass, int _asPort) {
        _portNum = _asPort;

        //
        //  Read the AS keystore (i.e. its private key)
        //  Failure codes to return are defined on the top
        //

        //
        //  Note :
        //    When you return a success DO-NOT forget to show the
        //    Activity panel using the line below and start the
        //    thread listening for connections
        //

        _layout.show(_appFrame.getContentPane(), "ActivityPanel");

        _thread = new AuthServerThread(this);
        _thread.start();
        return AuthServer.SUCCESS;
    }

    public int getPortNumber() {
        return _portNum;
    }

    public JTextArea getOutputArea() {

        return _activityPanel.getOutputArea();
    }

    //  main
    //  
    //  Construct the AS panel, read in the passwords and give the
    //  control back
    public static void main(String[] args) throws Exception {
        
        AuthServer as = new AuthServer();
        as.run();
    }
}
