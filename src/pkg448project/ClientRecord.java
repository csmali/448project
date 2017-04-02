//  ClientRecord.java
package pkg448project;

// Java
import java.util.*;
import java.math.BigInteger;

// socket
import java.net.*;
import java.io.*;

// Crypto
import java.security.*;
import java.security.spec.*;
import java.security.interfaces.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;

// You may need to expand this class for anonymity and revocation control.
public class ClientRecord {

    Socket _socket = null;

    public ClientRecord(Socket socket) {

        _socket = socket;
    }

    public Socket getClientSocket() {

        return _socket;
    }

    public String toString() {
        return _socket.toString();

    }

}
