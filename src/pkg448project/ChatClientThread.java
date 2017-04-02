/**
 *  Created 2/16/2003 by Ting Zhang
 *  Part of implementation of the ChatClient to receive
 *  all the messages posted to the chat room.
 */
package pkg448project;

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
    private String roomKey;

    public ChatClientThread(ChatClient client) {

        super("ChatClientThread");
        _client = client;
        _socket = client.getSocket();
        _outputArea = client.getOutputArea();
        roomKey = client.getRoomKey();
    }

    /*server threadden gelen mesajlar hashlere bakilip hashler dogru ise room key kullanilarak decrypt edilir
    decrypt edilen mesajlar panele basilir. */
    public void run() {

        try {

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(
                            _socket.getInputStream()));

            String receivedMsg;
            String line = "";

            String secretKeyString = "";
          

            while ((receivedMsg = in.readLine()) != null) {

                String hmac = CipherAct.calculateRFC2104HMAC((roomKey + CipherAct.calculateRFC2104HMAC(roomKey + receivedMsg.substring(0, receivedMsg.length() - 40), roomKey)), roomKey);
                String receivedEncryptedMsg = receivedMsg.substring(0, receivedMsg.length() - 40);
                String receivedHash = receivedMsg.substring(receivedEncryptedMsg.length(), receivedMsg.length());
                System.out.println("Received Full Message : " + receivedMsg);

                System.out.println("Received Encrypted Message : " + receivedEncryptedMsg);

                if (receivedHash.equals(hmac)) {
                    String decryptedMessage = new String(CipherAct.decrypt(receivedEncryptedMsg, roomKey));
                    System.out.println("Decrypted : " + new String(CipherAct.decrypt(receivedEncryptedMsg, roomKey)));
                    System.out.println("Received Hash : " + receivedHash);
                    System.out.println("Calculated Hash : " + hmac);
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

}
