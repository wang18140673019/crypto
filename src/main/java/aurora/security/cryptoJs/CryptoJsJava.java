package aurora.security.cryptoJs;
import java.io.*;
import java.util.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.*;
import javax.crypto.spec.*;
import org.apache.commons.codec.binary.Base64;

/**
 * Class which provides methods for encrypting and decrypting
 * strings using a DES encryption algorithm.
 * Strings can be encrypted and then are returned translated
 * into a Base64 Ascii String.
 *
 * @author  王子明
 * @version $Revision: 1.2 $
 */
public class CryptoJsJava {

    private final static String passswordKey = "1234567qwertyuiASDFGVFR8";
     
     private  CryptoJsJava(SecretKey key) throws Exception {
    }    

   
    public static String encryptBase64 (String unencryptedString) throws Exception {
        // Encode the string into bytes using utf-8
    	 Cipher encryptCipher = Cipher.getInstance("DES");
    	 SecretKey key = getSecretKey(passswordKey);
        encryptCipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] unencryptedByteArray = unencryptedString.getBytes("UTF8");

        // Encrypt
        byte[] encryptedBytes = encryptCipher.doFinal(unencryptedByteArray);

        // Encode bytes to base64 to get a string
        byte [] encodedBytes = Base64.encodeBase64(encryptedBytes);

        return new String(encodedBytes);
    }

    public static String decryptBase64 (String encryptedString) throws Exception {
        // Encode bytes to base64 to get a string
        byte [] decodedBytes = Base64.decodeBase64(encryptedString.getBytes());

        // Decrypt
        Cipher decryptCipher = Cipher.getInstance("DES");
   	    SecretKey key = getSecretKey(passswordKey);
   	     decryptCipher.init(Cipher.DECRYPT_MODE, key);
        byte[] unencryptedByteArray = decryptCipher.doFinal(decodedBytes);

        // Decode using utf-8
        return new String(unencryptedByteArray, "UTF8");
    }    
    
    
     private static SecretKey getSecretKey(String pasxwordKey){
    	DESKeySpec key = null;
		try {
			key = new DESKeySpec(passswordKey.getBytes());
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        SecretKeyFactory keyFactory = null;
		try {
			keyFactory = SecretKeyFactory.getInstance("DES");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
         try {
			return keyFactory.generateSecret(key);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
    }

    /**
     * Main unit test method.
     * @param args Command line arguments.
     *
     */
    public static void main(String args[]) {
        try {
            String unencryptedString = "子明Message";
            String encryptedString =CryptoJsJava.encryptBase64(unencryptedString);
            // Encrypted String:8dKft9vkZ4I=
            System.out.println("Encrypted String:"+encryptedString);

            //Decrypt the string
            unencryptedString =CryptoJsJava.decryptBase64(encryptedString);
            // UnEncrypted String:Message
            System.out.println("UnEncrypted String:"+unencryptedString);

        } catch (Exception e) {
            System.err.println("Error:"+e.toString());
        }
    }
}