//
//  X509CertificateGenerator.java
//
//  Modified by : Priyank Patel <pkpatel@cs.stanford.edu>
//                added the policies for the chat rooms A and B
//  Modified by :Murat Ak, Dec 2011
//                  Changed to java.security.cert
package Chat;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.*;
import java.security.*;
import java.math.BigInteger;
import java.security.cert.CertificateException;
//import javax.security.cert.*;
import java.security.cert.*;

public class X509CertificateGenerator {

    public static X509Certificate generateCertificate(
            Principal subjectName,
            PublicKey subjectPublicKey,
            Principal issuerName,
            PrivateKey issuerPrivateKey,
            String algorithm,
            BigInteger serialNumber,
            boolean allowRoomA,
            boolean allowRoomB) throws FileNotFoundException {


        CertificateFactory cf;
        X509Certificate cert = null;



        try {
            cf = CertificateFactory.getInstance("X.509");
            FileInputStream fileinputstream = new FileInputStream("????");
            cert = (X509Certificate) cf.generateCertificate(fileinputstream);

        } catch (CertificateException e) {

            System.out.println("X509 Certificate Generation Error: Certificate Exception");
            e.printStackTrace();
        } 

        return cert;

    }
}
