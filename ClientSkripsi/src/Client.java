import javax.swing.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.util.*;
import java.security.interfaces.RSAPublicKey;

public class Client extends JFrame implements ActionListener, MouseListener {
    private final JPanel panel;
    private final JLabel error, message;
    private Socket cSocket;
    private ObjectInputStream oin;
    private ObjectOutputStream oos;
    private String selectedItem;
    private int encrypt;
    private JList<String> filelist;
    private ArrayList<String> flist;

    public Client (String host, int port) {
	super("TCP CLIENT");
	panel = new JPanel(null);
        ButtonGroup radio = new ButtonGroup();

	JRadioButton blow = new JRadioButton("Blowfish");
        blow.setBounds(200, 320, 100, 25);
        radio.add(blow);
        panel.add(blow);
        
        JRadioButton rsa = new JRadioButton("RSA");
        rsa.setBounds(350, 320, 50, 25);
        radio.add(rsa);
        panel.add(rsa);

	JButton up = new JButton("Upload");
	up.setBounds(150, 380, 150, 35);
	panel.add(up);

	JButton down = new JButton("Download");
	down.setBounds(350, 380, 150, 35);
	panel.add(down);
        
        JButton refresh = new JButton("Refresh");
        refresh.setBounds(450, 50, 120, 20);
        panel.add(refresh);

	error = new JLabel("");
	error.setBounds(350, 430, 600, 25);
	panel.add(error);
        
        message = new JLabel("");
        message.setBounds(150, 430, 500, 25);
        panel.add(message);

	up.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
		if (encrypt == 1 || encrypt == 2) {
                    upClick(e);
                } else {
                    JOptionPane.showMessageDialog(null, "Please select the encryption method.", 
                            "Attention", JOptionPane.INFORMATION_MESSAGE);
                }
            }
	});

	down.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
		if (encrypt == 1 || encrypt == 2) {
                    downClick(e);
                } else {
                    JOptionPane.showMessageDialog(null, "Please select the encryption method.", 
                            "Attention", JOptionPane.INFORMATION_MESSAGE);
                }
            }
	});
        
        blow.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                encrypt = 1;
            }
        });
        
        rsa.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                encrypt = 2;
            }
        });
        
        refresh.addActionListener(new ActionListener() {
            public void actionPerformed(ActionEvent e) {
                refresh(e);
            }
        });
        
        defaultThings(host, port);
	getContentPane().add(panel);
        setSize(700, 500);
        setVisible(true);
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    }
    
    private void defaultThings(String host, int port) {
        try {
            cSocket = new Socket(host, port);
            System.out.println("Connected to server.");
            oin = new ObjectInputStream(cSocket.getInputStream());
            oos = new ObjectOutputStream(cSocket.getOutputStream());

            flist = (ArrayList<String>) oin.readObject();
            Arrays.sort(flist.toArray());

            JLabel servFiles = new JLabel("Files in the Server:");
            servFiles.setBounds(100, 50, 400, 50);
            panel.add(servFiles);

            filelist = new JList(flist.toArray());
            JScrollPane scroll = new JScrollPane(filelist);
            scroll.setBounds(100, 100, 480, 200);
            panel.add(scroll);
            filelist.addMouseListener(this);
	} catch (Exception exc) {
            System.out.println("Exception: " + exc.getMessage());
            error.setText("Exception:" + exc.getMessage());
            error.setBounds(300,125,600,50);
            panel.revalidate();
	}
    }

    public void mouseClicked(MouseEvent click) {
        if (click.getClickCount() == 1) {
            selectedItem = (String) filelist.getSelectedValue();
            panel.revalidate();
        }
    }

    public void mousePressed(MouseEvent e){}
    public void mouseEntered(MouseEvent e){}
    public void mouseExited(MouseEvent e){}
    public void mouseReleased(MouseEvent e){}

    public void upClick(ActionEvent e) {
	try {
            JFileChooser choose = new JFileChooser();
            int response = choose.showOpenDialog(null);
            
            if (response == JFileChooser.APPROVE_OPTION && choose.getSelectedFile() != null) {
                String name = choose.getSelectedFile().getName();
                File myFile = choose.getSelectedFile();
		
                String filex = "#" + name + "#";
                oos.writeObject(filex);
                oos.flush();

		System.out.println("Upload begins...");
		
                FileInputStream fis = new FileInputStream(myFile);
                byte[] myByte = new byte[fis.available()];
                fis.read(myByte);
                System.out.println("Plaintext size: " + (double) myByte.length / 1024);
                
                byte[] encryptedByte;
                long start, end, result;
                if (encrypt == 1) {
                    oos.writeObject("blow");
                    oos.flush();
                    
                    System.out.println("Encryption with Blowfish begin...");
                    clientBlowfish en = new clientBlowfish(myByte);
                    start = System.currentTimeMillis();
                    encryptedByte = en.crypting();
                    end = System.currentTimeMillis();
                    result = (end - start);
                    System.out.println("Encryption done.");
                    System.out.println("Encryption time: " + (float) result / 1000 + "s");
                    System.out.println("In milliseconds: " + result + "ms");
                    message.setText("Encryption time: " + (float) result / 1000);
                    
                    String sec = en.getKey();
                    System.out.println("Sending public key...");
                    oos.writeObject(sec);
                    oos.flush();
                    System.out.println("Public key sent.");
                } else {
                    oos.writeObject("rsa");
                    oos.flush();
                    
                    RSAPublicKey pub = (RSAPublicKey) oin.readObject();
                    System.out.println("Public key received.");
                    clientRSA en = new clientRSA(pub);
                    
                    System.out.println("Encryption with RSA begin...");
                    start = System.currentTimeMillis();
                    encryptedByte = en.cryption(myByte);
                    end = System.currentTimeMillis();
                    result = (end - start);
                    System.out.println("Encryption done.");
                    System.out.println("Encryption time: " + (float) result / 1000 + "s");
                    System.out.println("In milliseconds: " + result + "ms");
                    message.setText("Encryption time: " + (float) result / 1000);
                }
                
                oos.writeObject(encryptedByte);
                oos.flush();
            }
            
            flist = (ArrayList<String>) oin.readObject();
            String[] arr_temp = flist.toArray(new String[0]);
            Arrays.sort(arr_temp);
            filelist.setListData(arr_temp);
            panel.revalidate();
            
            System.out.println("Upload completed.");
                JOptionPane.showMessageDialog(null, "Upload completed.", 
                        "Attention", JOptionPane.INFORMATION_MESSAGE);
        } catch (Exception exc) {
            System.out.println("Exception: " + exc.getMessage());
            error.setText("Exception:" + exc.getMessage());
            panel.revalidate();
        }
    }

    public void downClick(ActionEvent e) {
        try {
            if (selectedItem != null) {
                JFileChooser choose = new JFileChooser();
                choose.setCurrentDirectory(null);
                choose.setDialogTitle("Select where to save...");
                choose.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                choose.setAcceptAllFileFilterUsed(false);
                int response = choose.showOpenDialog(null);

                if (response == JFileChooser.APPROVE_OPTION && choose.getSelectedFile() != null) {
                    String filex = "*" + selectedItem + "*";
                    oos.writeObject(filex);
                    oos.flush();
                        
                    System.out.println("Download begins...");
                    File f = new File(choose.getSelectedFile().getAbsolutePath() + "\\" + selectedItem);
                    byte[] decryptedByte;
                    long start, end, result;
                        
                    if (encrypt == 1) {
                        oos.writeObject("blow");
                        oos.flush();
                
                        String sec = (String) oin.readObject();
                        byte[] bytes = (byte[]) oin.readObject();
                            
                        System.out.println("Decryption with Blowfish begin...");
                        clientBlowfish de = new clientBlowfish(bytes, sec);
                        start = System.currentTimeMillis();
                        decryptedByte = de.crypting();
                        end = System.currentTimeMillis();
                        result = (end - start);
                        System.out.println("Decryption done.");
                        System.out.println("Decryption time: " + (float) result / 1000 + "s");
                        System.out.println("In milliseconds: " + result + "ms");
                        message.setText("Decryption time: " + (float) result / 1000 + "s");
                    } else {
                        oos.writeObject("rsa");
                        oos.flush();
                        
                        clientRSA de = new clientRSA();
                        RSAPublicKey pub = de.getPub();
                        
                        System.out.println("Sending public key...");
                        oos.writeObject(pub);
                        oos.flush();
                        System.out.println("Public key sent.");
                        
                        byte[] bytes = (byte[]) oin.readObject();
                
                        System.out.println("Decryption with RSA begin...");
                        start = System.currentTimeMillis();
                        decryptedByte = de.cryption(bytes);
                        end = System.currentTimeMillis();
                        result = (end - start);
                        System.out.println("Decryption done.");
                        System.out.println("Decryption time: " + (float) result / 1000 + "s");
                        System.out.println("In milliseconds: " + result + "ms");
                        message.setText("Decryption time: " + (float) result / 1000 + "s");
                    }
                        
                    FileOutputStream fos = new FileOutputStream(f);
                    fos.write(decryptedByte);
                    fos.flush();

                    System.out.println("Download completed");
                    JOptionPane.showMessageDialog(null, "Download completed.", 
                    "Attention", JOptionPane.INFORMATION_MESSAGE);
                    panel.revalidate();
                }
            }
        } catch (Exception exc) {
            System.out.println("Exception: " + exc.getMessage());
            error.setText("Exception:" + exc.getMessage());
            panel.revalidate();
        }
    }
    
    public void refresh(ActionEvent e) {
        try {
            String msg = "xUPDATEx";
            oos.writeObject(msg);
            oos.flush();
            
            flist = (ArrayList<String>) oin.readObject();
            String[] arr_temp = flist.toArray(new String[0]);
            Arrays.sort(arr_temp);
            filelist.setListData(arr_temp);
            panel.revalidate();
            System.out.println("Update received.");
        } catch (Exception ex) {
            System.out.println(ex.getMessage());
        }
    }

    public void actionPerformed(ActionEvent event) {}

    public static void main(String[] args) throws Exception {
        String ip_add = "";
        Object ip;
        int response = 0;
                
        while (ip_add.equals("")) {
            ip = JOptionPane.showInputDialog("Enter your IP address:");
            ip_add = ip.toString();
                    
            if(ip_add.equals("")) {
                JOptionPane.showMessageDialog(null, "Enter IP address first!", 
                "Attention", JOptionPane.INFORMATION_MESSAGE);
                ip_add = "";
            }
        }
        
        if (response != JOptionPane.CANCEL_OPTION || response != JOptionPane.CLOSED_OPTION) {
            new Client(ip_add, 2910);
        }
    }
}