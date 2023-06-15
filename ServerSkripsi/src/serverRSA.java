import java.math.BigInteger;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.*;
import javax.crypto.Cipher;

public class serverRSA {
    private BigInteger n, e, d, phi;
    private final int mode;
    private SecureRandom rand;
    private RSAPublicKey pub;
    private RSAPrivateKey priv;
    private final Cipher cipher;
    
    //bundle enkripsi
    public serverRSA(RSAPublicKey pubkey) throws Exception {
        mode = Cipher.ENCRYPT_MODE;
        pub = pubkey;
        cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
    
    //bundle dekripsi
    public serverRSA() throws Exception {
        mode = Cipher.DECRYPT_MODE;
        generateN();
        e = generateE();
        d = generateD();
        pubKeyGen();
        privKeyGen();
        cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
    }
    
    public RSAPublicKey getPub() {
        return pub;
    }
    
    private void generateN() {
        rand = new SecureRandom();
        
        BigInteger p = BigInteger.probablePrime(2048, rand);
        BigInteger q = BigInteger.probablePrime(2048, rand);
        
        n = p.multiply(q);
        phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
    }
    
    private BigInteger generateE () {
        e = BigInteger.probablePrime(64, rand);
        
        while(!(phi.gcd(e).equals(BigInteger.ONE))) {
            e = BigInteger.probablePrime(64, rand);
        }
        
        return e;
    }
    
    private BigInteger generateD() {
        return e.modInverse(phi);
    }
    
    private void pubKeyGen() throws Exception {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec spec = new RSAPublicKeySpec(n, e);
        pub = (RSAPublicKey) factory.generatePublic(spec);
    }
    
    private void privKeyGen() throws Exception {
        KeyFactory fact = KeyFactory.getInstance("RSA");
        RSAPrivateKeySpec spec = new RSAPrivateKeySpec(n, d);
        priv = (RSAPrivateKey) fact.generatePrivate(spec);
    }
    
    public byte[] cryption(byte[] bytes) throws Exception {
        byte[] scramble;
        byte[] toReturn = new byte[0];
        int len = (mode == Cipher.ENCRYPT_MODE)? 446 : 512; //untuk rsa biasa, pakai 117 : 128. Panjang kunci harus 1024
        byte[] buffer = new byte[len];
        
        if (mode == Cipher.ENCRYPT_MODE) {
            RSAPublicKey pubKey = pub;
            cipher.init(mode, pubKey);
        } else {
            RSAPrivateKey privKey = priv;
            cipher.init(mode, privKey);
        }
        
        for(int i = 0; i < bytes.length; i++) {
            if((i > 0) && (i % len == 0)) {
                scramble = cipher.doFinal(buffer);
                toReturn = append(toReturn, scramble);
                int newlen = len;
                
                if(i + len > bytes.length) {
                    newlen = bytes.length - i;
                }
                buffer = new byte[newlen];
            }
            buffer[i % len] = bytes[i];
        }
        
        if (mode == Cipher.ENCRYPT_MODE) {
            scramble = cipher.doFinal(buffer);
            toReturn = append(toReturn, scramble);
        }
        
        return toReturn;
    }
    
    private static byte[] append(byte[] prefix, byte[] suffix) {
        byte[] toReturn = new byte[prefix.length + suffix.length];
            
        for(int i = 0; i < prefix.length; i++) {
            toReturn[i] = prefix[i];
        }
            
        for(int i = 0; i < suffix.length; i++) {
            toReturn[i + prefix.length] = suffix[i];
        }
        
        return toReturn;
    }
}