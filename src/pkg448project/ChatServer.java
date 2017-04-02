package Chat;

// Java General
import java.util.*;
import java.net.*;
import java.io.*;

// Crypto
import java.security.*;

public class ChatServer {

    // Hashtable'lar Room A ve Room B icin kullanici recordlarini tutarlar.
    private Hashtable _clientsRoomA;
    private Hashtable _clientsRoomB;

    /* A ve B odalarinin simetrik anahtarlari String seklinde tanimlanmistir.
     * Daha sonra bu keyler kullanici hangi odaya login olduysa ona gonderilecektir.
     */
    private String roomA_Key = "01234567890123456789012345678901";
    private String roomB_Key = "98765432109876543210987654321098";
    private int _clientID = 0;
    private int _port;
    private String _hostName = null;

    private ServerSocket _serverSocket = null;

    //Bu dictionaryde kullanici isimleri ve karsisinda bu kullanicilara ait sifrelerin 15 kez Hashli halleri tutulmaktadir.
    private String[][] keyDictionary = new String[5][2];

    //Private ve Public key Server tarafindan ilk acilista olusturulur.
    private PrivateKey priv;
    private PublicKey pub;
    PrintWriter _out = null;

    public ChatServer(int port) throws NoSuchAlgorithmException, NoSuchProviderException, FileNotFoundException, IOException {

        /* 1. sutunda kullanici adi
    	 * 2. sutunda passwordun 15 kez Hashli hali bulunmakta
    	 * (Password ile kullanici adi aynidir.)
    	 * Sadece cs470, cs471, cs472, cs473 ve cs474 adli kullanicilar kayitli halde bulunmakta.
         */
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

        /* Private ve public key cifti olusturulur.
         * RSA 2048 bit kullanilmaktadir.
         * Sonrasinda public key, clientlar tarafindan okunmak uzere dosyaya yazilir.
         */
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        priv = pair.getPrivate();
        pub = pair.getPublic();
        byte[] key = pub.getEncoded();
        FileOutputStream keyfos = new FileOutputStream("serverPublicKey");
        keyfos.write(key);
        keyfos.close();
        try {

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

            //Server'a baglanmak isteyen clientin ID'si ve o ID'ye atadigimiz random sayiyi tutuyoruz.
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

                /* Hello mesaji geldiyse ve clientIDyi alirsa:
                 * Random bir integer yaratilip server'a gonderilir.
                 * Eger kullanici sistemde bulunmassa 77777 gonderilir.
                 * Client 77777 gorurse gecersiz kullanici oldugunu anlar.
                 */
                if (connectionStage == 0 && line.length() > 5 && line.substring(0, 5).equals("Hello")) {
                    Random randomGenerator = new Random();
                    randomInt = randomGenerator.nextInt(65536);
                    clientID = line.substring(5);

                    String clientExist = findInKeyDictionary(clientID);
                    if (!clientExist.equals("Unknown User")) {
                        _out.println(randomInt);
                        connectionStage++;
                    } else {
                        _out.println("77777");
                        socket.close();
                        continue;
                    }
                }

                line = _in.readLine();

                /* Public ile sifrelenmis bir metin gelmisse bu metin decrypt edilir.
                 * Ardindan ilk parca olan random int ile xorlanmis ardindan hashlanmis kisim karsilastirilir.
                 * Eger ayniysa kullanici istedigi odaya katilabilir.
                 * Gecici anahtar bu ilk kismin ilk 32 karakteri secilir.
                 */
                if (connectionStage == 1 && line.length() > 5) {
                    String decrypted = CipherAct.decryptWithPrivate(line, priv);
                    if (decrypted.length() == 41) {
                        String clientFirstPart = decrypted.substring(0, 40);
                        String clientSecondPart = decrypted.substring(40);
                        String passHash = findInKeyDictionary(clientID);
                        String serverFirstPart = CipherAct.sha1(CipherAct.xor(passHash, randomInt + ""));

                        if (clientFirstPart.equals(serverFirstPart) && clientSecondPart.contains("A")) {
                            String encryptedRoomKey = CipherAct.encrypt(roomA_Key, serverFirstPart.substring(0, 32));
                            ClientRecord clientRecord = new ClientRecord(socket);
                            _clientsRoomA.put(new Integer(_clientID++), clientRecord);
                            _out.println(encryptedRoomKey);
                            ChatServerThread thread = new ChatServerThread(this, socket);
                            clientID = "";
                            connectionStage = 0;
                            thread.start();
                        } else if (clientFirstPart.equals(serverFirstPart) && clientSecondPart.contains("B")) {
                            String encryptedRoomKey = CipherAct.encrypt(roomB_Key, serverFirstPart.substring(0, 32));
                            ClientRecord clientRecord = new ClientRecord(socket);
                            _clientsRoomB.put(new Integer(_clientID++), clientRecord);
                            _out.println(encryptedRoomKey);
                            ChatServerThread thread = new ChatServerThread(this, socket);
                            clientID = "";
                            connectionStage = 0;
                            thread.start();
                        } else {
                            _out.println("88888");
                            socket.close();
                            continue;
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
