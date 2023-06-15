import java.io.*;
import java.net.*;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import javax.swing.*;

public class Server extends JFrame {
    private JPanel here;
    private JList<String> flist;
    private String dir;
    private ArrayList<String> names;
    
    public Server(int port) {
        directorySelect();
        theGUI();
        serverListening(port);
    }
    
    private void directorySelect() {
        int response;
        JFileChooser choose = new JFileChooser();

        choose.setCurrentDirectory(null);
        choose.setDialogTitle("Select server directory.");
        choose.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        choose.setAcceptAllFileFilterUsed(false);
        response = choose.showOpenDialog(null);

        if (response == JFileChooser.APPROVE_OPTION) {
            dir = choose.getSelectedFile().getAbsolutePath();
            System.out.println(dir + " selected.");
        } else {
            System.out.println("Server directory set to default.");
            dir = choose.getCurrentDirectory().getAbsolutePath();
        }
    }
    
    private void theGUI() {
        here = new JPanel(null);
        
        File ff = new File(dir);
        names = new ArrayList<String>(Arrays.asList(ff.list()));
        Arrays.sort(names.toArray());
        
        JLabel directoryName = new JLabel("Server directory: " + dir);
        directoryName.setBounds(100, 50, 400, 50);
        here.add(directoryName);
        
        flist = new JList(names.toArray());
        JScrollPane scroll = new JScrollPane(flist);
        scroll.setBounds(100, 100, 480, 200);
        here.add(scroll);
        here.revalidate();
        
        add(here);
        setTitle("TCP SERVER");
        setSize(700, 500);
        setVisible(true);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
    
    private void serverListening(int port) {
        int id = 1;
        
        try {
            ServerSocket welcomeSocket = new ServerSocket(port);
            
            while (true) {
                Socket connection = welcomeSocket.accept();
                System.out.println("Client with ID " + id + " connected from " + connection.getInetAddress().getHostName() + "...");
                
                new Thread(new ClientHandler(connection)).start();
                id++;
            }
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
    }
    
    private class ClientHandler implements Runnable {
        private final Socket cs;
        private ObjectOutputStream oos;
        private ObjectInputStream oin;
        
        public ClientHandler(Socket ss) {
            cs = ss;
            
            try {
                oos = new ObjectOutputStream(cs.getOutputStream());
                oin = new ObjectInputStream(cs.getInputStream());

                oos.writeObject(names);
                oos.flush();
            } catch (Exception ex) {
                System.out.println(ex.getMessage());
            }
        }
        
        public void run() {
            try {
                do {
                    String filename = (String) oin.readObject();
                    String ch = filename.substring(0, 1);
                    String namex, path;
                    int n;
                    serverBlowfish en, de;
                    serverRSA enc, dec;

                    if (ch.equals("*")) {
                        n = filename.lastIndexOf("*");
                        namex = filename.substring(1, n);
                        System.out.println("Request to download file " + namex + " from " + cs.getInetAddress().getHostName() + "...");
                        path = dir + "\\" + namex;
                        System.out.println("Transfer begins...");
                    
                        String encryption = (String) oin.readObject();
                        File myFile = new File(path);
                        FileInputStream fis = new FileInputStream(myFile);
                        byte[] myByte = new byte[fis.available()];
                        fis.read(myByte);
                        System.out.println("Plaintext size: " + (double) myByte.length / 1024);
                    
                        byte[] encryptedByte;
                        long start, end, result;
                        double inKb;
                        if (encryption.equals("blow")) {
                            System.out.println("Encryption with Blowfish begin...");
                            en = new serverBlowfish(myByte);
                            start = System.currentTimeMillis();
                            encryptedByte = en.crypting();
                            end = System.currentTimeMillis();
                            result = (end - start);
                            inKb = encryptedByte.length / 1024;
                            System.out.println("Encryption done.");
                            System.out.println("Encryption time: " + (float) result / 1000 + "s");
                            System.out.println("In milliseconds: " + result + "ms");
                            System.out.println("Ciphertext size: " + inKb + "kb");
                    
                            String sec = en.getKey();
                            System.out.println("Sending public key...");
                            oos.writeObject(sec);
                            oos.flush();
                            System.out.println("Public key sent.");
                        } else {
                            RSAPublicKey pub = (RSAPublicKey) oin.readObject();
                            System.out.println("Public key received.");
                            enc = new serverRSA(pub);
                            
                            System.out.println("Encryption with RSA begin...");
                            start = System.currentTimeMillis();
                            encryptedByte = enc.cryption(myByte);
                            end = System.currentTimeMillis();
                            result = (end - start);
                            inKb = encryptedByte.length / 1024;
                            System.out.println("Encryption done.");
                            System.out.println("Encryption time: " + (float) result / 1000 + "s");
                            System.out.println("In milliseconds: " + result + "ms");
                            System.out.println("Ciphertext size: " + inKb + "kb");
                        }

                        oos.writeObject(encryptedByte);
                        oos.flush();
                        System.out.println("Transfer completed.");
                    }  else if (ch.equals("#")) {
                        n = filename.lastIndexOf("#");
                        namex = filename.substring(1, n);
                        System.out.println("Request to upload file " + namex + " from " + cs.getInetAddress().getHostName() + "...");
                        path = dir + "\\" + namex;
                        System.out.println("Receiving...");

                        String encryption = (String) oin.readObject();
                        File f = new File(path);
                        FileOutputStream fos = new FileOutputStream(f);
                    
                        byte[] decryptedByte;
                        long start, end, result;
                        if (encryption.equals("blow")) {
                            String sec = (String) oin.readObject();
                            byte[] bytes = (byte[]) oin.readObject();
                        
                            System.out.println("Decryption with Blowfish begin...");
                            de = new serverBlowfish(bytes, sec);
                            start = System.currentTimeMillis();
                            decryptedByte = de.crypting();
                            end = System.currentTimeMillis();
                            result = (end - start);
                            System.out.println("Decryption done.");
                            System.out.println("Decryption time: " + (float) result / 1000 + "s");
                            System.out.println("In milliseconds: " + result + "ms");
                        } else {
                            dec = new serverRSA();
                            RSAPublicKey pub = dec.getPub();
                        
                            System.out.println("Sending public key...");
                            oos.writeObject(pub);
                            oos.flush();
                            System.out.println("Public key sent.");
                            byte[] bytes = (byte[]) oin.readObject();
                        
                            System.out.println("Decryption with RSA begin...");
                            start = System.currentTimeMillis();
                            decryptedByte = dec.cryption(bytes);
                            end = System.currentTimeMillis();
                            result = (end - start);
                            System.out.println("Decryption done.");
                            System.out.println("Decryption time: " + (float) result / 1000 + "s");
                            System.out.println("In milliseconds: " + result + "ms");
                        }

                        fos.write(decryptedByte);
                        fos.flush();
                        System.out.println("File received.");
                        
                        File refresh = new File(dir);
                        names = new ArrayList<String>(Arrays.asList(refresh.list()));
                        oos.writeObject(names);
                        oos.flush();
                        
                        String[] arr_temp = names.toArray(new String[0]);
                        Arrays.sort(arr_temp);
                        flist.setListData(arr_temp);
                        here.revalidate();
                    } else if (filename.equals("xUPDATEx")) {
                        File refresh = new File(dir);
                        names = new ArrayList<String>(Arrays.asList(refresh.list()));
                        oos.writeObject(names);
                        oos.flush();
                        System.out.println("Update sent.");
                    } else {
                        System.out.println("Invalid input.");
                    }
                } while (cs.isClosed() != true);
            } catch (Exception ex) {
                System.out.println(ex.getMessage());
            }
        }
    }
    
    public static void main(String[] args) {
        int portN = 2910;
        new Server(portN);
    }
}