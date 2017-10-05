import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Scanner;

public class Receiver {
    private static final int BLOCK_SIZE = 128; // 128, 192, or 256
    private static final String AES_TRANSFORMATION = "AES/ECB/NoPadding";

    private static final String PRIVATE_KEY_FILE_NAME = "YPrivate.key";
    private static final String ENVELOPE_KEY_FIlE_NAME = "kxy.rsacipher";

    private static Scanner stdIn = new Scanner(System.in);

    public static void main (String[] args) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeyException, BadPaddingException,
            IllegalBlockSizeException, IOException,
            InvalidAlgorithmParameterException, InvalidKeySpecException,
            ClassNotFoundException {
        // Generate rsa private key
        PrivateKey rsaPrivateKeyY = generateRsaKeyFromFile(
                PRIVATE_KEY_FILE_NAME);

        // Ask user for message file name
        System.out.print("Message output filename: ");
        String outFileName = stdIn.nextLine();

        // RSA decrypt the envelope key from file
        byte[] envelopeKey =
                getEnvelopeKey(ENVELOPE_KEY_FIlE_NAME, rsaPrivateKeyY);
        writeToFile(envelopeKey, outFileName + ".kmk", false);

        // Read Envelope contents one block at a time.
        decryptEnvelopeContents(outFileName + ".aescipher", envelopeKey,
                outFileName);

        // Append Kxy to KMK file
        writeToFile(envelopeKey, outFileName + ".kmk", true);

        // Compute SHA256(K||M||K) && Compare to stored value
        boolean hashesMatch = doKeyedHashMacCheck(outFileName);
        System.out.println("Hashes match: " + hashesMatch);
    }

    // Assignment implementing methods

    private static PrivateKey generateRsaKeyFromFile (String fileName) throws
            ClassNotFoundException, NoSuchAlgorithmException,
            InvalidKeySpecException {
        // Generate RSA key from YPrivate.key
        File yPrivFile = new File(fileName);
        FileInputStream yPrivIn = null;
        try {
            yPrivIn = new FileInputStream(yPrivFile);
        } catch (FileNotFoundException ex) {
            System.out.println("Make sure you copy the receiver's private key" +
                    " to this directory");
            System.exit(1);
        }
        try (ObjectInputStream oips = new ObjectInputStream(yPrivIn)) {
            BigInteger m = (BigInteger)oips.readObject();
            BigInteger e = (BigInteger)oips.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(keySpec);
        } catch (IOException ioEx) {
            System.out.println("Serialization error.");
            System.exit(1);
        }
        return null;
    }

    private static byte[] getEnvelopeKey (String envelopeKeyFileName,
                                          PrivateKey rsaPrivateKey) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException {
        byte[] rsaCipherText = null;
        try {
            rsaCipherText = getFileBytes(envelopeKeyFileName);
        } catch (FileNotFoundException e) {
            System.out.println("RSA encrypted Kxy not found. Did you copy the" +
                    " file over?");
            System.exit(1);
        }

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, rsaPrivateKey);
        byte[] rsaPlainText = cipher.doFinal(rsaCipherText);

        StringBuilder result = new StringBuilder();
        for (byte bb : rsaPlainText) {
            result.append(String.format("%02X ", bb));
        }
        System.out.println("Kxy = " + result);
        return rsaPlainText;
    }

    private static void decryptEnvelopeContents (String envelopeFileName,
                                                 byte[] envelopeKey,
                                                 String outFileName) throws
            NoSuchAlgorithmException, NoSuchPaddingException,
            InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, IOException,
            InvalidAlgorithmParameterException {

        Cipher cipherAES = Cipher.getInstance(AES_TRANSFORMATION);
        SecretKeySpec
                key = new SecretKeySpec(envelopeKey, "AES");
        cipherAES.init(Cipher.DECRYPT_MODE, key);
        File cipherTextFile = new File(envelopeFileName);
        if (!cipherTextFile.exists()) {
            System.out.println("Make sure you copy the encrypted message file" +
                    " to this directory.");
            System.exit(1);
        }

        RandomAccessFile f = new RandomAccessFile(envelopeFileName, "r");
        byte[] b = new byte[(int)f.length()];
        f.readFully(b);



        long numBlocks = b.length / BLOCK_SIZE;
        if (b.length % BLOCK_SIZE != 0) {
            numBlocks += 1;
        }
        for (int i = 0; i < numBlocks; i++) {
            byte[] bSub = Arrays.copyOfRange( b, i*BLOCK_SIZE,
                    i*BLOCK_SIZE+BLOCK_SIZE);

            byte[] plainBlock = cipherAES.doFinal(bSub);

            // Write/append the result to the output file.
            writeToFile(plainBlock, outFileName, true);
            // Append the result to the KMK file
            writeToFile(plainBlock, outFileName + ".kmk", true);
        }
    }

    private static boolean doKeyedHashMacCheck (
            String outFileName) throws NoSuchAlgorithmException,
            IOException {
        File checkFile = new File(outFileName + ".kmk");
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

        byte[] computedHash = dis.getMessageDigest().digest();

        RandomAccessFile f = new RandomAccessFile(outFileName + ".khmac",
                "r");
        byte[] macHash = new byte[(int)f.length()];
        f.readFully(macHash);


        StringBuilder computedHashStringBuilder = new StringBuilder();
        for (byte bb : computedHash) {
            computedHashStringBuilder.append(String.format("%02X ", bb));
        }

        StringBuilder macHashStringBuilder = new StringBuilder();
        for (byte bb : macHash) {
            macHashStringBuilder.append(String.format("%02X ", bb));
        }

        System.out.println("Computed hash: " + computedHashStringBuilder
                .toString());
        System.out.println("Expected hash: " + macHashStringBuilder
                .toString());
        return (computedHashStringBuilder
                .toString().equals(macHashStringBuilder.toString()));
    }

    // Utility methods

    private static void writeToFile (byte[] data, String fileName,
                                     boolean append) throws
            IOException {
        // Open or create fileName
        File file = new File(fileName);
        FileOutputStream fos = new FileOutputStream(file, append);

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
}
