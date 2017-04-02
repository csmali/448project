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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
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
    private Hashtable _clientsRoomA;
    private Hashtable _clientsRoomB;
    private String roomA_Key = "01234567890123456789012345678901";
    private String roomB_Key = "98765432109876543210987654321098";
    private int _clientID = 0;
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
    private PrivateKey priv;
    private PublicKey pub;
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
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        priv = pair.getPrivate();
        pub = pair.getPublic();
        byte[] key = pub.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("serverPublicKey");
        keyfos.write(key);
        keyfos.close();
        try {

            _clients = new Hashtable();
            _clientsRoomA = new Hashtable();
            _clientsRoomB = new Hashtable();
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

            String clientID = "";
            int randomInt = 0;
            int connectionStage = 0;
            while (true) {

                Socket socket = _serverSocket.accept();
                _out = new PrintWriter(socket.getOutputStream(), true);
                BufferedReader _in = new BufferedReader(
                        new InputStreamReader(
                                socket.getInputStream()));

                String line = _in.readLine();

                //Hello mesaj� ve clientIdyi al�rsa
                if (connectionStage == 0 && line.length() > 5 && line.substring(0, 5).equals("Hello")) {
                    Random randomGenerator = new Random();
                    randomInt = randomGenerator.nextInt(65536);
                    clientID = line.substring(5);
                    System.out.println("1" + line);

                    String clientExist = findInKeyDictionary(clientID);
                    if (!clientExist.equals("Unknown User")) {
                        _out.println(randomInt);
                        connectionStage++;
                    }
                }

                line = _in.readLine();
                System.out.println("2" + line + "  " + line.length());
                // line=line.substring(0,line.length()-1);
                //Public ile sifrelenmis bilgileri al�rsa >10 ilk hello mesaj�yla jarismasin diye, sacma olabilir...
                if (connectionStage == 1 && line.length() > 5) {
                    System.out.println("3");

                    String decrypted = CipherAct.decryptWithPrivate(line, priv);
                    System.out.println("4");
                    if (decrypted.length() == 41) {
                        System.out.println(decrypted);

                        String clientFirstPart = decrypted.substring(0, 40);
                        String clientSecondPart = decrypted.substring(40);
                        System.out.println(clientFirstPart);

                        System.out.println(clientSecondPart);

                        String passHash = findInKeyDictionary(clientID);
                        String serverFirstPart = CipherAct.sha1(CipherAct.xor(passHash, randomInt + ""));
                        System.out.println("CLIENT SECOND PART : " + clientSecondPart);

                        if (clientFirstPart.equals(serverFirstPart) && clientSecondPart.contains("A")) {
                            System.out.println("A ya koyduk");
                            String encryptedRoomKey = CipherAct.encrypt(roomA_Key, serverFirstPart.substring(0, 32));
                            ClientRecord clientRecord = new ClientRecord(socket);
                            _clientsRoomA.put(new Integer(_clientID++), clientRecord);
                            _out.println(encryptedRoomKey);
                            ChatServerThread thread = new ChatServerThread(this, socket);
                            clientID = "";
                            connectionStage = 0;
                            thread.start();
                        } else if (clientFirstPart.equals(serverFirstPart) && clientSecondPart.contains("B")) {
                            System.out.println("B ya koyduk");

                            String encryptedRoomKey = CipherAct.encrypt(roomB_Key, serverFirstPart.substring(0, 32));
                            ClientRecord clientRecord = new ClientRecord(socket);
                            _clientsRoomB.put(new Integer(_clientID++), clientRecord);
                            _out.println(encryptedRoomKey);
                            ChatServerThread thread = new ChatServerThread(this, socket);
                            clientID = "";
                            connectionStage = 0;
                            thread.start();
                        }
                    }
                }

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

    public String findInKeyDictionary(String clientID) {
        for (int i = 0; i < keyDictionary.length; i++) {
            if (keyDictionary[i][0].equals(clientID)) {
                return keyDictionary[i][1];
            }
        }
        return "Unknown User";
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

    public String getRoomKeyA() {
        return roomA_Key;
    }

    public String getRoomKeyB() {
        return roomB_Key;
    }
}
