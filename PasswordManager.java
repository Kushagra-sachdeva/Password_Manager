import java.awt.*;
import javax.swing.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.util.ArrayList;
import java.security.SecureRandom;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
class SplashScreen {
    JFrame frame;
    JLabel image = new JLabel(new ImageIcon("download.png"));
    JLabel text = new JLabel("PASSWORD & NOTES MANAGER");
    JProgressBar progressBar = new JProgressBar();
    JLabel message = new JLabel();

    SplashScreen() {
        createGUI();
        addImage();
        addText();
        addProgressBar();
        runningPBar();
    }

    public void createGUI() {
        frame = new JFrame();
        frame.setUndecorated(true);
        frame.setSize(400, 400);
        frame.setLocationRelativeTo(null);
        JPanel gradientPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                Graphics2D g2d = (Graphics2D) g;
                Color startColor = new Color(182, 244, 146); 
                Color endColor = new Color(51, 139, 147);  
                GradientPaint gradient = new GradientPaint(0, 0, startColor, getWidth(), getHeight(), endColor);
                g2d.setPaint(gradient);
                g2d.fillRect(0, 0, getWidth(), getHeight());
            }
        };
        gradientPanel.setLayout(null); 
        frame.setContentPane(gradientPanel); 
        frame.setVisible(true);
    }

    public void addImage() {
        image.setBounds(100, 50, 200, 200);
        frame.add(image);
    }

    public void addText() {
        text.setFont(new Font("Verdana", Font.BOLD, 20));
        text.setBounds(50, 260, 300, 40);
        text.setForeground(Color.WHITE);
        frame.add(text);
    }

    public void addProgressBar() {
        progressBar.setBounds(50, 320, 300, 20);
        progressBar.setBorderPainted(true);
        progressBar.setStringPainted(true);
        progressBar.setBackground(Color.WHITE);
        progressBar.setForeground(new Color(0x1E5631)); 
        frame.add(progressBar);
    }
    public void runningPBar(){
        int i=0;
        while( i<=100)
        {
            try{
                Thread.sleep(40);   
                progressBar.setValue(i);    
                i++;
                if(i==100)
                    frame.dispose();
            }catch(Exception e){
                e.printStackTrace();
            }
        }
    }
}

class HashtablePassword implements hashTableMap {
    private final int useProbe;    
    private Entry[] entries;       
    private final float loadFactor;     
    private int size, used;         
    private final Entry NIL = new Entry(null, null);

    private static class Entry{
        Object key, value;
        Entry(Object k, Object v){
            key = k;    value = v;
        }
    }
    public HashtablePassword(int capacity, float loadFactor, int useProbe){
        entries = new Entry[capacity];
        this.loadFactor = loadFactor;
        this.useProbe = useProbe;
    }

    public int hash(Object key){
        return (key.hashCode() & 0x7FFFFFFF) % entries.length;
    }

    private int nextProbe(int h, int i){
        return (h+i) % entries.length;  
    }

    private void rehash(){ 
        Entry[] oldEntries = entries;
        entries = new Entry[2*entries.length+1];
        for (Entry entry : oldEntries) {
            if (entry == NIL || entry == null) continue;
            int h = hash(entry.key);
            for (int x = 0; x < entries.length; x++) {
                int j = nextProbe(h, x);
                if (entries[j] == null) {
                    entries[j] = entry;
                    break;
                }
            }
            used = size;
        }
    }

    @Override
    public int add_Acc(Object Account, Object passwd) {
        if(used > (loadFactor*entries.length))rehash();
        int h = hash(Account);
        for (int i = 0; i < entries.length; i++){
            int j = (h+i) % entries.length;
            Entry entry = entries[j];
            if(entry==null){
                entries[j]= new Entry(Account, passwd);
                ++size;
                ++used;
                return h;
            }
            if(entry == NIL)continue;
            if(entry.key.equals(Account)){
                Object oldValue = entry.value;
                entries[j].value = passwd;
                return (int) oldValue;
            }
        }
        return h;
    }

    @Override
    public Object get_Acc(Object Account) {
        int h = hash(Account);
        for(int i = 0; i < entries.length; i++){
            int j = nextProbe(h , i);
            Entry entry = entries[j];
            if(entry == null)break;
            if(entry == NIL)continue;
            if(entry.key.equals(Account)) return entry.value;
        }
        return null;
    }

    @Override
    public Object remove_Acc(Object Account) {
        int h = hash(Account);
        for(int i = 0; i < entries.length; i++){
            int j = nextProbe(h,i);
            Entry entry = entries[j];
            if(entry == NIL)continue;
            if(entry.key.equals(Account)){
                Object Value = entry.value;
                entries[j] = NIL;
                size--;
                return Value;
            }
        }
        return null;
    }
}
class CryptoUtil 
{

    Cipher ecipher;
    Cipher dcipher;
    byte[] salt = {
        (byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32,
        (byte) 0x56, (byte) 0x35, (byte) 0xE3, (byte) 0x03
    };

    int iterationCount = 19;

    public CryptoUtil() {

    }

    /**
     *
     * @param secretKey Key used to encrypt data
     * @param plainText Text input to be encrypted
     * @return Returns encrypted text
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     *
     */
    public String encrypt(String secretKey, String plainText)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            UnsupportedEncodingException,
            IllegalBlockSizeException,
            BadPaddingException {

        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
      
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);


        ecipher = Cipher.getInstance(key.getAlgorithm());
        ecipher.init(Cipher.ENCRYPT_MODE, key, paramSpec);
        String charSet = "UTF-8";
        byte[] in = plainText.getBytes(charSet);
        byte[] out = ecipher.doFinal(in);
        String encStr = new String(Base64.getEncoder().encode(out));
        return encStr;
    }

    /**
     * @param secretKey Key used to decrypt data
     * @param encryptedText encrypted text input to decrypt
     * @return Returns plain text after decryption
     * @throws java.security.NoSuchAlgorithmException
     * @throws java.security.spec.InvalidKeySpecException
     * @throws javax.crypto.NoSuchPaddingException
     * @throws java.security.InvalidKeyException
     * @throws java.security.InvalidAlgorithmParameterException
     * @throws java.io.UnsupportedEncodingException
     * @throws javax.crypto.IllegalBlockSizeException
     * @throws javax.crypto.BadPaddingException
     */
    public String decrypt(String secretKey, String encryptedText)
            throws NoSuchAlgorithmException,
            InvalidKeySpecException,
            NoSuchPaddingException,
            InvalidKeyException,
            InvalidAlgorithmParameterException,
            UnsupportedEncodingException,
            IllegalBlockSizeException,
            BadPaddingException,
            IOException {
    
        KeySpec keySpec = new PBEKeySpec(secretKey.toCharArray(), salt, iterationCount);
        SecretKey key = SecretKeyFactory.getInstance("PBEWithMD5AndDES").generateSecret(keySpec);
     
        AlgorithmParameterSpec paramSpec = new PBEParameterSpec(salt, iterationCount);
    
        dcipher = Cipher.getInstance(key.getAlgorithm());
        dcipher.init(Cipher.DECRYPT_MODE, key, paramSpec);
        byte[] enc = Base64.getDecoder().decode(encryptedText);
        byte[] utf8 = dcipher.doFinal(enc);
        String charSet = "UTF-8";
        String plainStr = new String(utf8, charSet);
        return plainStr;
    }    
   
}

class PasswordGenerator {
    private static final SecureRandom random = new SecureRandom();
    private static final String caps="ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private static final String small_caps="abcdefghijklmnopqrstuvwxyz";
    private static final String Numeric="1234567890";
    private static final String special_char="~!@#$%^&*(_+{}|:_[?]>=<";
    private static final String dic = caps + small_caps + Numeric + special_char;

    public String generatePassword(int len) {
        StringBuilder password= new StringBuilder();
        for (int i = 0; i <len ; i++) {
            int index = random.nextInt(dic.length());
            password.append(dic.charAt(index));
        }
        return password.toString();
    }

}


interface hashTableMap {

    Object get_Acc(Object Account);
    int add_Acc(Object Account, Object passwd);
    Object remove_Acc(Object Account);
}

class PasswordManager implements ActionListener {
    HashtablePassword data = new HashtablePassword(15,0.5F,0);
    JFrame frame;
    JFrame frame2;
    JLabel background;
    Container conn1,conn2;
    JLabel lAcc,lPass;
    JTextArea encryptPasswdArea, genePassArea, searchPassArea;
    JButton PassGeneBtn,PassEncryptBtn, PassStoreBtn, PassSearchBtn, AccAddBtn, PassDeleteBtn;
    JTextField tAcc,tPass;
    JButton addNoteBtn;
    JLabel addNoteLabel;
    JTextArea tNote;
    JButton addNote;
    JFrame conn3;

    ArrayList<String> notes = new ArrayList<>(); 

    @Override
    public void actionPerformed(ActionEvent e) { }
    public static void FrameGUI(JFrame frame){
        frame.setVisible(true);
        frame.setLayout(null);
        frame.setLocationRelativeTo(null);
    }
    public static void ContainerGUI(Container conn) {
        conn.setVisible(true);
        conn.setBackground(new Color(182, 244, 146)); 
        conn.setLayout(null);
    }

    public void GUIButtonsSetting(JButton btn){
        btn.setBackground(new Color(0XFB2576));
        btn.setForeground(Color.WHITE);
        btn.setBorder(BorderFactory.createLineBorder(Color.BLACK, 3));
        btn.setFocusable(false);
        Cursor crs = new Cursor(Cursor.HAND_CURSOR); 
        btn.setCursor(crs);
        Font fn = new Font("MV Boli", Font.BOLD, 15);
        btn.setFont(fn);
    }

    public void StoringGUI()
    {
        frame2 = new JFrame("Store your passwords");
        frame2.setBounds(1400, 300, 800, 500);
        frame2.setSize(400,400);
        FrameGUI(frame2);
        conn2 = frame2.getContentPane();
        ContainerGUI(conn2);
        Font fn = new Font("MV Boli", Font.BOLD, 20);
        lAcc = new JLabel("ACCOUNT NAME");
        lAcc.setBounds(90, 23, 380, 20);
        lAcc.setFont(fn);
        conn2.add(lAcc);

        tAcc = new JTextField();
        tAcc.setBounds(90,70,200,50);
        tAcc.setFont(fn);
        tAcc.setBorder(BorderFactory.createLineBorder(Color.BLACK, 3));
        tAcc.setForeground(Color.DARK_GRAY);
        conn2.add(tAcc);
        lPass = new JLabel("ACCOUNT PASSWORD");
        lPass.setBounds(90, 160, 380, 20);
        lPass.setFont(fn);
        conn2.add(lPass);

        tPass = new JTextField();
        tPass.setBounds(90,200,200,50);
        tPass.setFont(fn);
        tPass.setBorder(BorderFactory.createLineBorder(Color.BLACK, 3));
        tPass.setForeground(Color.DARK_GRAY);
        conn2.add(tPass);

        AccAddBtn = new JButton("STORE");
        AccAddBtn.setBounds(120, 290, 150, 50);
        conn2.add(AccAddBtn);
        GUIButtonsSetting(AccAddBtn);
    }
    public void textArea(String Pass,JTextArea TA){
        TA.setText(Pass);
        Font fn = new Font("MV Boli", Font.BOLD, 20);
        TA.setWrapStyleWord(true);
        TA.setLineWrap(true);
        TA.setCaretPosition(0);
        TA.setEditable(false);
        TA.setFont(fn);

    }
    PasswordManager() {

        frame = new JFrame("Password Manager");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(400,650);
        frame.setResizable(false);
        ImageIcon img = new ImageIcon("background.png");
        background = new JLabel("",img,JLabel.CENTER);
        background.setBounds(0,0,400,650);
        background.setVisible(true);
        frame.add(background);
    
        FrameGUI(frame);

        conn1 = frame.getContentPane();
        ContainerGUI(conn1);

        PassGeneBtn = new JButton("GENERATE PASSWORD");
        PassGeneBtn.setBounds(90, 20, 220, 40);
        conn1.add(PassGeneBtn);
        GUIButtonsSetting(PassGeneBtn);
        PassGeneBtn.addActionListener(e -> {
        if(PassGeneBtn ==e.getSource())
        {
            try{
                int len = Integer.parseInt(JOptionPane.showInputDialog("Enter the password length"));
                if(len>4)
                {
    
                    PasswordGenerator pass = new PasswordGenerator();
                    String passwd = pass.generatePassword(len);
                    genePassArea = new JTextArea(5,4);
                    textArea(passwd,genePassArea);
                    JOptionPane.showMessageDialog(conn1,new JScrollPane(genePassArea),"Copy your password",JOptionPane.INFORMATION_MESSAGE);

                }
                else JOptionPane.showMessageDialog (conn1,"Password length must be greater than 8!","Invalid Input Error",JOptionPane.WARNING_MESSAGE);

            }
            catch(Exception ex){JOptionPane.showMessageDialog(conn1,"Write something","EXIT!",JOptionPane.ERROR_MESSAGE);}
        }
    }
    );
 

        JButton EncryptBtn = new JButton("ENCRYPT Text");
        EncryptBtn.setBounds(90, 90, 220, 40);
        conn1.add(EncryptBtn);
        GUIButtonsSetting(EncryptBtn);
        EncryptBtn.addActionListener(e -> {
            if(EncryptBtn ==e.getSource())
            {
                try{
                    String text = JOptionPane.showInputDialog("Enter the text to encrypt");
                    String secretKey = JOptionPane.showInputDialog("Enter the secret key");
                    if(text.length()>0 && secretKey.length()>0)
                    {
                      
                        CryptoUtil pass1 = new CryptoUtil();
                        String passwd = pass1.encrypt(secretKey, text); 
                        genePassArea = new JTextArea(5,4); 
                        textArea(passwd,genePassArea); 
                        JOptionPane.showMessageDialog(conn1,new JScrollPane(genePassArea),"Copy your password",JOptionPane.INFORMATION_MESSAGE); // showing the encrypted text

                    }
                    else JOptionPane.showMessageDialog (conn1,"Write something","Invalid Input Error",JOptionPane.WARNING_MESSAGE);

                }
                catch(Exception ex){JOptionPane.showMessageDialog(conn1,"Write something","EXIT!",JOptionPane.ERROR_MESSAGE);}
            }
        }
        );

        JButton DecryptBtn = new JButton("DECRYPT Text"); 
        DecryptBtn.setBounds(90, 160, 220, 40);
        conn1.add(DecryptBtn);
        GUIButtonsSetting(DecryptBtn);
        DecryptBtn.addActionListener(e -> {
            if(DecryptBtn ==e.getSource())
            {
                try{
                    String text = JOptionPane.showInputDialog("Enter the text to decrypt"); 
                    String secretKey = JOptionPane.showInputDialog("Enter the secret key"); 
                    if(text.length()>0 && secretKey.length()>0) 
                    {
                        CryptoUtil pass1 = new CryptoUtil();
                        String passwd = pass1.decrypt(secretKey, text); 
                        genePassArea = new JTextArea(5,4); 
                        textArea(passwd,genePassArea); 
                        JOptionPane.showMessageDialog(conn1,new JScrollPane(genePassArea),"Decrypted text",JOptionPane.INFORMATION_MESSAGE); // showing the decrypted text

                    }
                    else JOptionPane.showMessageDialog (conn1,"Password length must be greater than 8!","Invalid Input Error",JOptionPane.WARNING_MESSAGE);

                }
                catch(Exception ex){JOptionPane.showMessageDialog(conn1,"Write something","EXIT!",JOptionPane.ERROR_MESSAGE);}
            }
        }
        );
        PassStoreBtn = new JButton("STORE PASSWORD");
        PassStoreBtn.setBounds(90, 230, 220, 40);
        conn1.add(PassStoreBtn);
        GUIButtonsSetting(PassStoreBtn);
        PassStoreBtn.addActionListener(e -> {
            if(PassStoreBtn ==e.getSource())
            {
                try{
                    StoringGUI();
                    AccAddBtn.addActionListener(e4 -> {
                        if (AccAddBtn == e4.getSource()) {
                            String account_name = tAcc.getText(); 
                            String acc_pass = tPass.getText(); 
                            if (account_name.isEmpty() && acc_pass.isEmpty()) {
                                JOptionPane.showMessageDialog(conn2,"unable to store your password!","ERROR",JOptionPane.ERROR_MESSAGE);
                            }
                            else{
                   
                                data.add_Acc(account_name,acc_pass); 
                                JOptionPane.showMessageDialog(conn2, "Account added Successfully !");
                                tAcc.setText(null);
                                tPass.setText(null);
                            }
                        }
                      }
                    );
                }
           catch(Exception ex) {JOptionPane.showMessageDialog(conn2,"Write something","EXIT",JOptionPane.ERROR_MESSAGE);}
            }
        }
        );

        PassSearchBtn = new JButton("SEARCH PASSWORD");
        GUIButtonsSetting(PassSearchBtn);
        PassSearchBtn.setBounds(90, 300, 220, 40);
        conn1.add(PassSearchBtn);
        PassSearchBtn.addActionListener(e ->{
            if (PassSearchBtn ==e.getSource()){
                try{
                    String acc_name = JOptionPane.showInputDialog("Enter your Account Name"); 
                    if (!acc_name.isBlank()) { 
                        Object pass = data.get_Acc(acc_name.toLowerCase()); 
                        if(pass!=null) {
                            searchPassArea = new JTextArea(4,5); 
                            textArea(String.valueOf(pass), searchPassArea); 
                            JOptionPane.showMessageDialog(conn1, new JScrollPane(searchPassArea), "Copy your password", JOptionPane.INFORMATION_MESSAGE);
                        }
                        else JOptionPane.showMessageDialog(conn1, "Account not Found!");
                    }
                }
                catch (Exception ex){
                    JOptionPane.showMessageDialog(conn1,"Write something","EXIT",JOptionPane.ERROR_MESSAGE);
                    }
                }
            }
        );
        PassDeleteBtn = new JButton("DELETE PASSWORD");
        GUIButtonsSetting(PassDeleteBtn);
        PassDeleteBtn.setBounds(90, 370, 220, 40);
        conn1.add(PassDeleteBtn);
        PassDeleteBtn.addActionListener(e -> {
            if (PassDeleteBtn == e.getSource()) {
                try {
                    String acc_name = JOptionPane.showInputDialog("Enter the Account Name"); 
                    if (!acc_name.isBlank()) {
                        data.remove_Acc(acc_name.toLowerCase()); 
                        JOptionPane.showMessageDialog(conn1, "Delete successfully!"); 
                    }
                    else JOptionPane.showMessageDialog(conn1, "Account not found!", "INFO", JOptionPane.INFORMATION_MESSAGE);
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Write something", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }

        }
        );

        addNoteBtn = new JButton("ADD NOTE");
        GUIButtonsSetting(addNoteBtn);
        addNoteBtn.setBounds(90, 440, 220, 40);
        conn1.add(addNoteBtn);
        addNoteBtn.addActionListener(e -> {
            if (addNoteBtn == e.getSource()) {
                try {
                    NoteGUI();
                   
                    addNote.addActionListener(e4 -> {
                        if (addNote == e4.getSource()) {
                            String note = tNote.getText(); 
                            if (note.isEmpty()) {
                                JOptionPane.showMessageDialog(conn3, "unable to store your note!", "ERROR", JOptionPane.ERROR_MESSAGE);
                            } else {
                              
                                notes.add(note); 
                                JOptionPane.showMessageDialog(conn3, "Note added Successfully !");
                                conn3.setVisible(false);
                                tNote.setText(null);
                            }
                        }
                    });
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn3, "Write something", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
        );
        
  
        JButton getNoteBtn = new JButton("GET NOTE");
        GUIButtonsSetting(getNoteBtn);
        getNoteBtn.setBounds(90, 510, 220, 40);
        conn1.add(getNoteBtn);
        getNoteBtn.addActionListener(e -> {
            if (getNoteBtn == e.getSource()) {
                try {
                    String allNotes = notes.get(notes.size() - 1); 
                    if (allNotes.isEmpty()) { 
                        JOptionPane.showMessageDialog(conn1, "No note found!", "INFO", JOptionPane.INFORMATION_MESSAGE); // showing the message
                    } else {
                        searchPassArea = new JTextArea(4, 5); 
                        textArea(allNotes, searchPassArea); 
                        JOptionPane.showMessageDialog(conn1, new JScrollPane(searchPassArea), "Get your notes", JOptionPane.INFORMATION_MESSAGE); // showing the message
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(conn1, "Add a note before trying to retrive", "EXIT", JOptionPane.ERROR_MESSAGE);
                }
            }
        }
        );

    }
    private void NoteGUI() {

        conn3 = new JFrame("Add Note");
        conn3.setSize(500, 500);
        conn3.setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        conn3.setLocationRelativeTo(null);
        conn3.setLayout(null);
        conn3.setVisible(true);
        conn3.setResizable(false);
         addNoteLabel = new JLabel("Add Note");
        addNoteLabel.setBounds(200, 20, 100, 30);
        conn3.add(addNoteLabel);

     
        tNote = new JTextArea(10, 10);
        tNote.setBounds(100, 60, 300, 300);
        conn3.add(tNote);

      
         addNote = new JButton("ADD NOTE");
        GUIButtonsSetting(addNote);
        addNote.setBounds(140, 380, 220, 30);
        conn3.add(addNote);
    }

 
    public static void main(String[] args) {
        
        new SplashScreen();
        try {
            new PasswordManager();
        }catch (Exception ex) { ex.printStackTrace(); }
 }
}