import java.io.*;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Scanner;

public class KeyGen {
    public static void main (String[] args) throws NoSuchAlgorithmException,
            InvalidKeySpecException, IOException {
        SecureRandom random = new SecureRandom();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024, random);  //1024: key size in bits

        // Create RSA KeyPair for X
        KeyPair pairX = generator.generateKeyPair();
        Key pubKeyX = pairX.getPublic();
        Key privKeyX = pairX.getPrivate();

        saveKeyFiles("X", pubKeyX, privKeyX);

        // Create RSA KeyPair for Y
        KeyPair pairY = generator.generateKeyPair();
        Key pubKeyY = pairY.getPublic();
        Key privKeyY = pairY.getPrivate();

        saveKeyFiles("Y", pubKeyY, privKeyY);

        // Symmetric key
        Scanner stdIn = new Scanner(System.in);
        System.out.print("Enter 16 character symmetric key: ");
        String keyString = stdIn.nextLine();
        while (keyString.length() != 16) {
            System.out.println("That was not 16 characters long. Try again");
            System.out.print("Enter 16 character symmetric key: ");
            keyString = stdIn.nextLine();
        }
        FileWriter fileWriter = new FileWriter(new File("symmetric.key"));
        fileWriter.write(keyString);
        fileWriter.close();
    }

    private static void saveKeyFiles (String keyName, Key pubKey, Key
            privKey) throws NoSuchAlgorithmException, InvalidKeySpecException,
            IOException {
        KeyFactory factory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec pubKSpec = factory.getKeySpec(pubKey,
                RSAPublicKeySpec.class);
        RSAPrivateKeySpec privKSpec = factory.getKeySpec(privKey,
                RSAPrivateKeySpec.class);
        String fileNamePub = keyName + "Public.key";
        String fileNamePriv = keyName + "Private.key";

        try (ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileNamePub)))) {
            oout.writeObject(pubKSpec.getModulus());
            oout.writeObject(pubKSpec.getPublicExponent());
            oout.close();
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        }

        try (ObjectOutputStream oout = new ObjectOutputStream(
                new BufferedOutputStream(new FileOutputStream(fileNamePriv)))) {
            oout.writeObject(privKSpec.getModulus());
            oout.writeObject(privKSpec.getPrivateExponent());
            oout.close();
        } catch (Exception e) {
            throw new IOException("Unexpected error", e);
        }
    }
}
