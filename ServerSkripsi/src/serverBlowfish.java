import java.security.Key;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class serverBlowfish {
    private final String key;
    private final byte[] theByte;
    private final int mode;
    
    public serverBlowfish(byte[] bytes) {
        theByte = bytes;
        mode = Cipher.ENCRYPT_MODE;
        key = randomString();
    }
    
    public serverBlowfish(byte[] bytes, String sec) {
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
        int len = 56; //key 128 bit
        String alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ" + "0123456789" + "abcdefghijklmnopqrstuvxyz";
        StringBuilder sb = new StringBuilder(len);
        
        for(int i = 0; i < len; i++) {
            int index = (int) (alpha.length() * Math.random());
            sb.append(alpha.charAt(index));
        }
        
        String finalRand = sb.toString();
        
        return finalRand;
    }
}