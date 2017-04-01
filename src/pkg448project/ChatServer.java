//
// ChatServer.java
// Created by Ting on 2/18/2003
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package Chat;

// Java General
import java.util.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;

// Crypto
import java.security.*;
import java.security.cert.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.security.auth.x500.*;
import javax.xml.bind.DatatypeConverter;
//import sun.security.x509.*;

public class ChatServer {

    private Hashtable _clients;
//      private Hashtable _clientsRoomA;
//      private Hashtable _clientsRoomB;
    private int _clientID = 0;
    private Hashtable _clientsRoomA;
    private Hashtable _clientsRoomB;
    private int _port;
    private String _hostName = null;
    // Some hints: security related fields.
    private String SERVER_KEYSTORE = "serverKeys";
    private char[] SERVER_KEYSTORE_PASSWORD = "123456".toCharArray();
    private char[] SERVER_KEY_PASSWORD = "123456".toCharArray();
    private ServerSocket _serverSocket = null;
    private SecureRandom secureRandom;
    private KeyStore serverKeyStore;
    private String[][] keyDictionary = new String[5][2];
    PrivateKey priv;
    PublicKey pub;
//    private KeyManagerFactory keyManagerFactory;
//    private TrustManagerFactory trustManagerFactory;
    PrintWriter _out = null;

    public ChatServer(int port) throws NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException {

        //keys and hashes
        keyDictionary[0][0] = "cs470";
        keyDictionary[0][1] = "1f6488a959bba9dd4e02aa2031fe0516b5d6db9b";
        keyDictionary[1][0] = "cs471";
        keyDictionary[1][1] = "a49f49518226833a2fc57fa2917ad3e7db20ddce";
        keyDictionary[2][0] = "cs472";
        keyDictionary[2][1] = "91b03fb14d943ce1f89ffe36254b727879f4024e";
        keyDictionary[3][0] = "cs473";
        keyDictionary[3][1] = "3ee7f460090dba4eef9574511cd926a00aabcf76";
        keyDictionary[4][0] = "cs474";
        keyDictionary[4][1] = "5a1b9d140572d7eec4776d359c3209e295b1f2fe";
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA", "SUN");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(1024, random);
        KeyPair pair = keyGen.generateKeyPair();
        priv = pair.getPrivate();
        pub = pair.getPublic();
        byte[] key = pub.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("serverPublicKey");
        keyfos.write(key);
        keyfos.close();
        try {

            _clients = new Hashtable();
            _serverSocket = null;
            _clientID = -1;
            _port = port;
            InetAddress serverAddr = InetAddress.getByName(null);
            _hostName = serverAddr.getHostName();

        } catch (UnknownHostException e) {

            _hostName = "0.0.0.0";

        }
    }

    public static void main(String args[]) {
        args = new String[1];
        args[0] = "7777";
        try {

            if (args.length != 1) {

                //  Might need more arguments if extending for extra credit
                System.out.println("Usage: java ChatServer portNum");
                return;

            } else {

                int port = Integer.parseInt(args[0]);
                ChatServer server = new ChatServer(port);
                server.run();
            }

        } catch (NumberFormatException e) {

            System.out.println("Useage: java ChatServer host portNum");
            e.printStackTrace();
            return;

        } catch (Exception e) {

            System.out.println("ChatServer error: " + e.getMessage());
            e.printStackTrace();
        }
    }

    /**
     * *
     *
     * Your methods for setting up secure connection
     *
     */
    public void run() {

        try {

            _serverSocket = new ServerSocket(_port);
            System.out.println("ChatServer is running on "
                    + _hostName + " port " + _port);

            while (true) {

                Socket socket = _serverSocket.accept();
                _out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader _in = new BufferedReader(
                        new InputStreamReader(
                                socket.getInputStream()));
                String line;
                boolean connectionEstablished = false;
                while (!connectionEstablished) {
                    while ((line = _in.readLine()) != null) {
                        System.out.println(line);
                        connectionEstablished = true;
                        if (line.contains("Hello")) {
                            Random randomGenerator = new Random();
                            int randomInt = randomGenerator.nextInt(65536);
                            _out.println(randomInt);
                            break;
                        }

                    }

                    while ((line = _in.readLine()) != null) {
                        System.out.println(line);
                        break;

                    }
                    System.out.println("Connection is granted");

                }
                System.out.println("Ciktim");

                ClientRecord clientRecord = new ClientRecord(socket);
                _clients.put(new Integer(_clientID++), clientRecord);
                ChatServerThread thread = new ChatServerThread(this, socket);

                thread.start();
            }

            //_serverSocket.close();
        } catch (IOException e) {

            System.err.println("Could not listen on port: " + _port);
            System.exit(-1);

        } catch (Exception e) {

            e.printStackTrace();
            System.exit(1);

        }
    }

    public Hashtable getClientRecords() {

        return _clients;
    }

    public Hashtable getClientRecordsA() {

        return _clientsRoomA;
    }

    public Hashtable getClientRecordsB() {

        return _clientsRoomB;
    }

}
