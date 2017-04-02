package Chat;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;

public class CipherAct {

    private static byte[] iv = {0x0a, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x0c, 0x0d, 0x0a, 0x01, 0x02, 0x03, 0x04, 0x0b, 0x0c, 0x0d};
    private static final String HMAC_SHA1_ALGORITHM = "HmacSHA1";

    /*
    Simetrik encryption icin kullanilan metod. 
    2 yerde kullanilmistir 
    -Hash degerleri clientten servera gonderildikten sonra iki tarafta da oldugunu bildigimiz bu hash degerlerinin 32 bytelik kismi ile
    roomkeyler sifrelenmistir ve serverdan clientlara gonderilmistir .Ardindan clientlar bu keyleri hashler ile mesaji decrypt ederek hesaplar
    -Kullanildigi ikinci yer ise bu roomkeyleri alan kullanicilarin kendi aralarinda haberlesmesi esnasinda bu encrypt metodu kullanilir.
     */
    public static String encrypt(String plaintext, String key) throws Exception {
        byte[] decodedKey = key.getBytes("UTF-8");
        //   byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ips = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, originalKey, ips);
        byte[] encryptedMessage = cipher.doFinal(plaintext.getBytes("ISO-8859-1"));
        return Base64.getEncoder().encodeToString(encryptedMessage);

    }

    /*
     Simetrik decryption icin kullanilan metod. 
    Simetrik encryption yapildiktan sonra 2 string olarak ciphertext ve keyi alarak AES decryption uygular.

     */
    public static String decrypt(String ciphertext, String key) throws Exception {
        byte[] decodedKey = key.getBytes("UTF-8");

        byte[] encryptedTextBytes = Base64.getDecoder().decode(ciphertext);
        //    byte[] decodedKey = Base64.getDecoder().decode(key);
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        IvParameterSpec ips = new IvParameterSpec(iv);
        cipher.init(Cipher.DECRYPT_MODE, originalKey, ips);
        return new String(cipher.doFinal(encryptedTextBytes), "ISO-8859-1");

    }

    /*
    Server ve clientler arasi roomkeyler degistirilmeden once haberlesmeyi saglayan asimetrik sifreleme metodudur.
    Server calismaya basladiginda yaratilan public key serverPublicKey dosyasina yazilir ve encrypt edilmek istendiginde
    asagidaki metod cagrilarak dosyadan public key okunur ve clientlar bu metod ile serverla encrypted haberlesmeye baslar
    
     */
    public static String encryptWithPublic(String msg) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        Path path = Paths.get("serverPublicKey");
        byte[] pubBytes = Files.readAllBytes(path);
        PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pubBytes));
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedMessage = cipher.doFinal(msg.getBytes("ISO-8859-1"));
        return Base64.getEncoder().encodeToString(encryptedMessage);
    }

    /*
    Server aldigi mesajlari bu metodu kullanarak sahip oldugu private key ile acarak okur 
    ve ona gore islem yapar
     */
    public static String decryptWithPrivate(String encryptedText, PrivateKey priv) throws Exception {
        byte[] encryptedTextBytes = Base64.getDecoder().decode(encryptedText);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, priv);
        return new String(cipher.doFinal(encryptedTextBytes), "ISO-8859-1");
    }

    /*
     */
    public static String calculateRFC2104HMAC(String data, String key)
            throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        SecretKeySpec signingKey = new SecretKeySpec(key.getBytes(), HMAC_SHA1_ALGORITHM);
        Mac mac = Mac.getInstance(HMAC_SHA1_ALGORITHM);
        mac.init(signingKey);
        return toHexString(mac.doFinal(data.getBytes()));
    }

    /*
     */
    public static String sha1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuffer sb = new StringBuffer();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }

        return sb.toString();
    }

    /*
     */
    public static String xor(String s, String key) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            sb.append((char) (s.charAt(i) ^ key.charAt(i % key.length())));
        }
        String result = sb.toString();
        return result;
    }

    private static String toHexString(byte[] bytes) {
        Formatter formatter = new Formatter();

        for (byte b : bytes) {
            formatter.format("%02x", b);
        }

        return formatter.toString();
    }
}
