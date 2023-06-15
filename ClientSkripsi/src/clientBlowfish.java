import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;

public class clientBlowfish {
    private final String key;
    private final byte[] theByte;
    private final int mode;
    
    public clientBlowfish(byte[] bytes) {
        theByte = bytes;
        mode = Cipher.ENCRYPT_MODE;
        key = randomString();
    }
    
    public clientBlowfish(byte[] bytes, String sec) {
        theByte = bytes;
        mode = Cipher.DECRYPT_MODE;
        key = sec;
    }
    
    public String getKey() {
        return key;
    }
    
    public byte[] crypting() throws Exception {
        Key seckey = new SecretKeySpec(key.getBytes(), "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish");
        cipher.init(mode, seckey);
        byte[] outBytes = cipher.doFinal(theByte);
        
        return outBytes;
    }
    
    private static String randomString() {
        int len = 56; //key 448 bit
        String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";
        StringBuilder sb = new StringBuilder(len);
        
        for(int i = 0; i < len; i++) {
            int index = (int) (alpha.length() * Math.random());
            sb.append(alpha.charAt(index));
        }
        
        String finalRand = sb.toString();
        
        return finalRand;
    }
    
    /*public static void main(String[] args) {
        long start1, start2, end1, end2, milli1, milli2;
        String key;
        File forTest = new File("C:/Users/user/Documents/dataClient/Client01.png");
        
        try {
            FileInputStream fis = new FileInputStream(forTest);
            byte[] newByte = new byte[fis.available()];
            byte[] encrypted, decrypted;
            fis.read(newByte);
            
            clientBlowfish testing = new clientBlowfish(newByte);
            start1 = System.currentTimeMillis();
            encrypted = testing.crypting();
            end1 = System.currentTimeMillis();
            System.out.println("Ciphertext size: " + (double) encrypted.length / 1024);
            milli1 = end1 - start1;
            key = testing.getKey();
            System.out.println("Encrypt milli: " + milli1);
            System.out.println("InSec: " + (float) milli1 / 1000);
            
            clientBlowfish testing2 = new clientBlowfish(encrypted, key);
            start2 = System.currentTimeMillis();
            decrypted = testing2.crypting();
            end2 = System.currentTimeMillis();
            milli2 = end2 - start2;
            System.out.println("Decrypt milli: " + milli2);
            System.out.println("InSec: " + (float) milli2 / 1000);
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
    }*/
}