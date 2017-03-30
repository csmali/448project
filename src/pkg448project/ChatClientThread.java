/**
 *  Created 2/16/2003 by Ting Zhang
 *  Part of implementation of the ChatClient to receive
 *  all the messages posted to the chat room.
 */
package Chat;

// socket
import java.net.*;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

//  Swing
import javax.swing.JTextArea;

//  Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import java.util.Formatter;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import javax.xml.bind.DatatypeConverter;

public class ChatClientThread extends Thread {

    private ChatClient _client;
    private JTextArea _outputArea;
    private Socket _socket = null;
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";
    private static SecretKey secretKey;

    public ChatClientThread(ChatClient client) {

        super("ChatClientThread");
        _client = client;
        _socket = client.getSocket();
        _outputArea = client.getOutputArea();
    }

    public void run() {

        try {

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            _socket.getInputStream()));

            String receivedMsg;
            String secretKeyString = "";

            while ((receivedMsg = in.readLine()) != null) {
                try (BufferedReader br = new BufferedReader(new FileReader("secretKeyString.txt"))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        secretKeyString = line;
                    }
                }
                System.out.println("SecretKeyEncoded" + secretKeyString);
                String hmac = calculateRFC2104HMAC((secretKeyString + calculateRFC2104HMAC(secretKeyString + receivedMsg.substring(0, receivedMsg.length() - 40), secretKeyString)), secretKeyString);
                String receivedEncryptedMsg = receivedMsg.substring(0, receivedMsg.length() - 40);
                String receivedHash = receivedMsg.substring(receivedEncryptedMsg.length(), receivedMsg.length());
                System.out.println("Received Full Message : " + receivedMsg);

                System.out.println("Received Encrypted Message : " + receivedEncryptedMsg);

                String decryptedMessage = decrypt(receivedEncryptedMsg.toCharArray());
                System.out.println("Decrypted : " + decrypt(receivedEncryptedMsg.toCharArray()));
                System.out.println("Received Hash : " + receivedHash);
                System.out.println("Calculated Hash : " + hmac);
                if (receivedHash.equals(hmac)) {
                    System.out.println("Hashes are same! Decrypted Message and hash will be sent to chat screen");
                    consumeMessage(decryptedMessage + "\n");

                }
            }

            _socket.close();

        } catch (IOException e) {

            e.printStackTrace();
        } catch (Exception ex) {
            Logger.getLogger(ChatClientThread.class.getName()).log(Level.SEVERE, null, ex);
        }

    }

    public void consumeMessage(String msg) {

        if (msg != null) {
            _outputArea.append(msg);
        }

    }

    public static String decrypt(char[] encryptedText) throws Exception {
        Path path = Paths.get("ivbytes");
        byte[] ivBytes = Files.readAllBytes(path);
        path = Paths.get("secretKey");
        byte[] getEncoded = Files.readAllBytes(path);

        byte[] encryptedTextBytes = DatatypeConverter.parseBase64Binary(new String(encryptedText));
        SecretKeySpec secretSpec = new SecretKeySpec(getEncoded, "AES");

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretSpec, new IvParameterSpec(ivBytes));

        byte[] decryptedTextBytes = null;

        try {
            decryptedTextBytes = cipher.doFinal(encryptedTextBytes);
        } catch (IllegalBlockSizeException e) {
            e.printStackTrace();
        } catch (BadPaddingException e) {
            e.printStackTrace();
        }

        return new String(decryptedTextBytes);

    }

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
}
