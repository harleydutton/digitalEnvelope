import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class Sender{
    private static int BUFFER_SIZE = 32 * 1024;
    private static int aesmultiple = 128;
    private static String LAST = "last.txt";
    private static int BLOCKSIZE = 1024;
    public static void main(String[] args) throws IOException {


        String nameOfM = getMessageName();
        makeKMK(nameOfM);
        makeKHMAC(nameOfM);
        makeAESCipher(nameOfM);
        makeRSACipher(nameOfM);



    }
    public static void makeRSACipher(String filename) throws IOException {
        String symmKey = "";
        try {
            Scanner s = new Scanner(new File("symmetric.key"));
            if(s.hasNextLine())symmKey=s.nextLine();
            s.close();
        } catch (FileNotFoundException e) {
            System.out.println("something went wrong while trying to read " +
                    "symmetric.key");
            e.printStackTrace();
        }
        SecureRandom random = new SecureRandom();

        PublicKey yPubKey = readPubKeyFromFile("YPublic.key");
        System.out.println(symmKey);

        byte[] ciphertext = new byte[0];
        byte[] inputbytes = symmKey.getBytes("UTF-8");
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, yPubKey, random);
            ciphertext = cipher.doFinal(inputbytes);

        } catch ( NoSuchPaddingException |
                NoSuchAlgorithmException | IllegalBlockSizeException |
                BadPaddingException | InvalidKeyException e) {
            System.out.println("something went wrong in the RSA encryption " +
                    "part of sender");
            e.printStackTrace();
        }



        if(ciphertext.length==0)System.out.println("kxy.cipher not created. " +
                "the byte[] was empty");
        else try {
            appendToFile(ciphertext, "kxy.rsacipher");
        } catch (IOException e) {
            System.out.println("failed to write kxy.rsacipher");
            e.printStackTrace();
        }
    }
    public static void makeAESCipher(String filename) throws IOException {
        File messageFile = new File(filename);
        long mLengthInBytes = messageFile.length();
        int blockSize = aesmultiple;
        int blocks = (int) (mLengthInBytes/blockSize);
        if(0!=mLengthInBytes%blockSize)blocks++;

        String symmKey = "";
        try {
            Scanner s = new Scanner(new File("symmetric.key"));
            if(s.hasNextLine())symmKey=s.nextLine();
            s.close();
        } catch (FileNotFoundException e) {
            System.out.println("something went wrong while trying to read " +
                    "symmetric.key");
            e.printStackTrace();
        }

        RandomAccessFile f = new RandomAccessFile(filename, "r");
        byte[] b = new byte[(int)f.length()];
        f.readFully(b);

        for(int i = 0 ; i < blocks; i++){

            byte[] bSub = Arrays.copyOfRange( b, i*aesmultiple,
                    i*aesmultiple+aesmultiple);
            try {
                appendToFile(encrypt(bSub, "AAAAAAAAAAAAAAAA", symmKey),
                        filename+".aescipher");
            } catch (Exception e) {
                System.out.println("Something went wrong in makeAESCipher()");
                e.printStackTrace();
            }


        }
    }

    public static byte[] encrypt(byte[] plaintext, String IV, String
            encryptionKey) throws
            Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding", "SunJCE");
        //Cipher cipher = Cipher.getInstance("AES/CFB8/NoPadding", "SunJCE");
        //Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding", "SunJCE");
        SecretKeySpec key = new SecretKeySpec(encryptionKey.getBytes("UTF-8"), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(plaintext);//plaintext.getbytes(utf8) was how
        // this was previously encoded but i have bytes not a string.
    }

    public static void makeKHMAC(String filename){
        byte[] hash = null;
        try {
            hash = md(filename+".kmk");
            System.out.println("#:"+filename+": " + md(filename));
        } catch (Exception e) {
            e.printStackTrace();
        }
        FileWriter fileWriter = null;
        try {
            if(hash.length==0)System.out.println("something went wrong with" +
                    " the hash. its a blank string");
            appendToFile(hash, filename + ".khmac");

        } catch (IOException e) {
            e.printStackTrace();
        }
    }
    public static String getMessageName() {

        String prevM = null;
        try {
            if(new File(LAST).exists()){
                Scanner s = new Scanner(new File(LAST));
                prevM = s.nextLine();
                s.close();}
        } catch (FileNotFoundException e) {
            e.printStackTrace(); }

        try{
            File file = new File(new File(LAST).getAbsolutePath
                    ());
            if(file.delete()){
                System.out.println(file.getName() + " is deleted!");
            }else{ System.out.println("failed to delete: "+file.getName()); }
        }catch(Exception e){ e.printStackTrace(); }

        try{
            File file = new File(new File(prevM+".aescipher").getAbsolutePath
                    ());
            if(file.delete()){
                System.out.println(file.getName() + " is deleted!");
            }else{ System.out.println("failed to delete: "+file.getName()); }
        }catch(Exception e){ e.printStackTrace(); }

        try{
            File file = new File(new File(prevM+".kmk")
                    .getAbsolutePath
                            ());
            if(file.delete()){
                System.out.println(file.getName() + " is deleted!");
            }else{ System.out.println("failed to delete: "+file.getName()); }
        }catch(Exception e){ e.printStackTrace(); }

        try{
            File file = new File(new File("kxy.rsacipher").getAbsolutePath
                    ());
            if(file.delete()){
                System.out.println(file.getName() + " is deleted!");
            }else{ System.out.println("failed to delete: "+file.getName()); }
        }catch(Exception e){ e.printStackTrace(); }

        try{
            File file = new File(new File(prevM+".khmac").getAbsolutePath
                    ());
            if(file.delete()){
                System.out.println(file.getName() + " is deleted!");
            }else{ System.out.println("failed to delete: "+file.getName()); }
        }catch(Exception e){ e.printStackTrace(); }




        //Files.deleteIfExists("")

        Scanner stdIn = new Scanner(System.in);
        System.out.println("Type the filename of M. "+
                "This is unsafe so don't use stupid characters.");
        String out = stdIn.nextLine();
        stdIn.close();
        System.out.println(out);
        try {
            appendToFile(out.getBytes(), LAST);
        } catch (IOException e) {
            e.printStackTrace();
        }

        return out;
    }
    public static void makeKMK(String filename){

        byte[] k = new byte[0];
        try {

            k = getFileBytes("symmetric.key");
            appendToFile(k, filename+".kmk");

            RandomAccessFile f = new RandomAccessFile(filename, "r");
            byte[] b = new byte[(int)f.length()];
            f.readFully(b);
            appendToFile(b, filename+".kmk");


            appendToFile(k, filename+".kmk");

        } catch (IOException e) {
            System.out.println("something went wrong with makeKMK()");
            e.printStackTrace();
        }


    }
    private static void appendToFile (byte[] data, String fileName) throws
            IOException {
        // Open or create fileName
        File file = new File(fileName);
        FileOutputStream fos;
        if (!file.exists()) {
            fos = new FileOutputStream(file);
        } else {
            fos = new FileOutputStream(file, true);
        }

        // append bytes to end of file
        fos.write(data);
        fos.close();
    }
    private static byte[] getFileBytes (String fileName) throws
            FileNotFoundException {
        return getFileBytes(new File(fileName));
    }
    private static byte[] getFileBytes (File file) throws
            FileNotFoundException {
        RandomAccessFile f = new RandomAccessFile(file, "r");
        byte[] b = null;
        try {
            b = new byte[(int)f.length()];
            f.readFully(b);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return b;
    }
    private static byte[] getFileBytes (File file, int off,
                                        int len) throws FileNotFoundException {
        RandomAccessFile f = new RandomAccessFile(file, "r");
        byte[] b = new byte[len];
        try {
            f.read(b, off, len);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return b;
    }
    public static byte[] md(String f) throws Exception {
        File checkFile = new File(f);
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        DigestInputStream dis = new DigestInputStream(new FileInputStream
                (checkFile), sha256);
        dis.on(true);
        int i = 0;
        while (dis.read(new byte[2048], i * 2048, 2048) < 0) {
            // Continue reading consecutive blocks 2048 big until the end of
            // file is reached (read returns -1)
            // This keeps the message digest up to date. I don't actually
            // care what the values read are so that's just a throw away array.
            i++;
        }

        return dis.getMessageDigest().digest();
    }
    public static PublicKey readPubKeyFromFile(String keyFileName)
            throws IOException {

        File yPubFile = new File(keyFileName);
        FileInputStream yPubIn = null;
        try {
            yPubIn = new FileInputStream(yPubFile);
        } catch (FileNotFoundException ex) {
            System.out.println("Make sure you copy the receiver's public"+
                    " key" +
                    " to this directory");
            System.exit(1);
        }

        ObjectInputStream oin = new ObjectInputStream(yPubIn);

        try {
            BigInteger m = (BigInteger) oin.readObject();
            BigInteger e = (BigInteger) oin.readObject();

            System.out.println("Read from " + keyFileName + ": modulus = " +
                    m.toString() + "\nexponent = " + e.toString() + "\n");

            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey key = factory.generatePublic(keySpec);

            return key;
        } catch (Exception e) {
            throw new RuntimeException("Spurious serialisation error", e);
        } finally {
            oin.close();
        }
    }
}
