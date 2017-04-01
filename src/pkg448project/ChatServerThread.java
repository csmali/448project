//
// ChatServerThread.java
// created 02/18/03 by Ting Zhang
// Modified : Priyank K. Patel <pkpatel@cs.stanford.edu>
//
package Chat;

// Java
import static Chat.ChatClient.calculateRFC2104HMAC;
import java.util.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

// Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.xml.bind.DatatypeConverter;

public class ChatServerThread extends Thread {

    private Socket _socket = null;
    private ChatServer _server = null;
    private Hashtable _records = null;
    private Hashtable _recordsA = null;
    private Hashtable _recordsB = null;
    private Hashtable _recordsSending = null;

    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    private static String salt;
    private static int iterations = 65536;
    private static int keySize = 256;
    static byte[] ivBytes;
    static SecretKey secretKey;
    ClientRecord clientRecord;

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

    public ChatServerThread(ChatServer server, Socket socket) {

        super("ChatServerThread");
        _server = server;
        _socket = socket;
        _records = server.getClientRecords();
        _recordsA = server.getClientRecordsA();
        _recordsB = server.getClientRecordsB();
        clientRecord = new ClientRecord(socket);

    }

    public void run() {

        try {

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            _socket.getInputStream()));

            String receivedMsg;
            String secretKeyString = "";

            while ((receivedMsg = in.readLine()) != null) {

                if (_recordsA.contains(clientRecord)) {
                    _recordsSending = _recordsA;
                } else {
                    _recordsSending = _recordsB;

                }
                Enumeration theClients = _recordsSending.elements();

                while (theClients.hasMoreElements()) {

                    ClientRecord c = (ClientRecord) theClients.nextElement();

                    Socket socket = c.getClientSocket();
                    try (BufferedReader br = new BufferedReader(new FileReader("secretKeyString.txt"))) {
                        String line;
                        while ((line = br.readLine()) != null) {
                            secretKeyString = line;
                        }
                    }
                    System.out.println("SecretKeyEncoded" + secretKeyString);

                    PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
                    String hmac = calculateRFC2104HMAC((secretKeyString + calculateRFC2104HMAC(secretKeyString + receivedMsg.substring(0, receivedMsg.length() - 40), secretKeyString)), secretKeyString);
                    String receivedEncryptedMsg = receivedMsg.substring(0, receivedMsg.length() - 40);
                    String receivedHash = receivedMsg.substring(receivedEncryptedMsg.length(), receivedMsg.length());
                    System.out.println("Received Full Message : " + receivedMsg);

                    System.out.println("Received Encrypted Message : " + receivedEncryptedMsg);

                    System.out.println("Received Hash : " + receivedHash);
                    System.out.println("Calculated Hash : " + hmac);
                    if (receivedHash.equals(hmac)) {
                        System.out.println("Hashes are same! Encrypted Message and hash will be sent to clients");
                        out.println(receivedMsg);

                    }
                }
            }

            _socket.shutdownInput();
            _socket.shutdownOutput();
            _socket.close();

        } catch (IOException e) {

            e.printStackTrace();
        } catch (SignatureException ex) {
            Logger.getLogger(ChatServerThread.class.getName()).log(Level.SEVERE, null, ex);
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(ChatServerThread.class.getName()).log(Level.SEVERE, null, ex);
        } catch (InvalidKeyException ex) {
            Logger.getLogger(ChatServerThread.class.getName()).log(Level.SEVERE, null, ex);
        } catch (Exception ex) {
            Logger.getLogger(ChatServerThread.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

}
