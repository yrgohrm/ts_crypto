package se.yrgo.crypto;

import java.io.*;
import java.nio.*;
import java.nio.charset.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import java.util.Base64.*;
import java.util.stream.*;
import javax.crypto.*;
import javax.crypto.spec.*;

/**
 * NOTHING IN THIS CLASS IS SUITABLE FOR USE IN THE REAL WORLD.
 * 
 * This class provides a few static methods to perform encryption and
 * decryption using RSA and AES.
 * 
 */
public final class CryptoUtils {
    public static final String PK_CIPHER = "RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING";
    public static final String BLOCK_CIPHER = "AES/GCM/NoPadding";
    public static final String SIGNATURE_CIPHER = "SHA384WithRSA";
    public static final String PK_KEY_TYPE = "RSA";
    public static final String BLOCK_KEY_TYPE = "AES";
    public static final int BLOCK_KEY_SIZE = 192;

    private static final String PRIVATE_KEY_SUFFIX = ".priv";
    private static final String PUBLIC_KEY_SUFFIX = ".pub";

    private CryptoUtils() {
    }

    /**
     * Decrypts a base64 encoded message (in UTF-8) using the given private key.
     * 
     * The message must be in the form <encrypted key>:<encrypted message>
     * 
     * The encrypted key should be a key for the BLOCK_CIPHER encrypted using
     * the public key matching this private key. The encrypted message will be
     * decrypted using block cipher and the recovered key.
     * 
     * @param message an encrypted message
     * @param pk the private key for the public key used to encrypt the message
     * @return the decoded message
     * 
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public static String decrypt(String message, PrivateKey pk)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException {

        String[] parts = message.split(":", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("invalid message format");
        }

        String keyPart = parts[0];
        String messagePart = parts[1];

        // create the cipher used to encrypt the block cipher's key info
        Cipher keyCipher = Cipher.getInstance(PK_CIPHER);
        keyCipher.init(Cipher.DECRYPT_MODE, pk);

        // decode the base64 part of the key and then
        // decrypt it using the private key
        byte[] encodedKey = Base64.getDecoder().decode(keyPart);
        byte[] decodedKeyAndIv = keyCipher.doFinal(encodedKey);

        // split the decrypted key info into tlen, ivsize and iv
        IntBuffer ivData = ByteBuffer.wrap(decodedKeyAndIv, 0, 8).asIntBuffer();
        int tlen = ivData.get();
        int ivSize = ivData.get();

        // create the crypto key and the iv
        SecretKey secretKey = new SecretKeySpec(decodedKeyAndIv, 8 + ivSize,
                decodedKeyAndIv.length - 8 - ivSize, BLOCK_KEY_TYPE);
        GCMParameterSpec spec = new GCMParameterSpec(tlen, decodedKeyAndIv, 8, ivSize);

        // create the block cipher
        Cipher decryptCipher = Cipher.getInstance(BLOCK_CIPHER);
        decryptCipher.init(Cipher.DECRYPT_MODE, secretKey, spec);

        // decrypt the message using the block cipher
        byte[] decodedMessage = Base64.getDecoder().decode(messagePart);
        byte[] decodedSecretMessageBytes = decryptCipher.doFinal(decodedMessage);

        return new String(decodedSecretMessageBytes, StandardCharsets.UTF_8);
    }

    /**
     * Decrypts the message given the private key and verifies the sender's signature with the given
     * public key.
     * 
     * The message must be in the form <message>:<signarure> where both the message and the
     * signature should be base64 encoded strings. The decrypted message is assumed to be in UTF-8.
     * 
     * @param message the encrypted message and signature
     * @param receiverKey the receiever's private key
     * @param senderKey the sender's public key
     * @return the decrypted message if the signature is valid
     * 
     * @throws SignatureException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws NoSuchPaddingException
     * @throws InvalidAlgorithmParameterException
     */
    public static Optional<String> decryptAndVerify(String message, PrivateKey receiverKey,
            PublicKey senderKey) throws SignatureException, InvalidKeyException,
            NoSuchAlgorithmException, IllegalBlockSizeException, BadPaddingException,
            NoSuchPaddingException, InvalidAlgorithmParameterException {
        String decryptedMessage = decrypt(message, receiverKey);

        String[] parts = decryptedMessage.split(":", 2);
        if (parts.length != 2) {
            throw new IllegalArgumentException("message have an invalid format");
        }

        String signaturePart = parts[0];
        String messagePart = parts[1];

        if (verify(messagePart, signaturePart, senderKey)) {
            return Optional.of(messagePart);
        }

        return Optional.empty();
    }

    /**
     * Encrypt a message, in UTF-8, with a signature. The string that will be encryptet will be in
     * the form <signature>:<message> the signature will be a base64 encoded string.
     * 
     * @param message the message to encrypt
     * @param receiverKey the public key of the receiver, used to encrypt
     * @param senderKey the private key of the sender, used to sign
     * @return a base64 encoded string consisting of the message and the signature
     * 
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws SignatureException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     */
    public static String encryptAndSign(String message, PublicKey receiverKey, PrivateKey senderKey)
            throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, SignatureException,
            InvalidParameterSpecException {
        String encodedSignature = sign(message, senderKey);
        return encrypt(encodedSignature + ":" + message, receiverKey);
    }

    /**
     * Encrypt the given message (in UTF-8) using a block crypto with a freshly generated key.
     * 
     * This generated key will be encrypted using the the public key.
     * 
     * The return value will be <encrypted key>:<encrypted message>, both which will be base64
     * encoded.
     * 
     * @param message the message to encrypt
     * @param pk the public key used
     * @return a string of the encrypted message and encrypted block crypto key
     * 
     * @throws NoSuchAlgorithmException
     * @throws NoSuchPaddingException
     * @throws InvalidKeyException
     * @throws IllegalBlockSizeException
     * @throws BadPaddingException
     * @throws InvalidParameterSpecException
     * @throws InvalidAlgorithmParameterException
     */
    public static String encrypt(String message, PublicKey pk)
            throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
            IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {

        // This method will generate a new block key and use that
        // to encrypt the actual message.
        // The block key, along with IV and tlen will be encrypted using the
        // given public key

        // Generate a fresh new key to use for this message
        KeyGenerator generator = KeyGenerator.getInstance(BLOCK_KEY_TYPE);
        generator.init(BLOCK_KEY_SIZE);
        SecretKey secKey = generator.generateKey();

        // Create the block cipher used to encrypt the main message
        Cipher encryptionCipher = Cipher.getInstance(BLOCK_CIPHER);
        encryptionCipher.init(Cipher.ENCRYPT_MODE, secKey);

        // Create the pk cipher used to encrypt the block cipher key and info
        Cipher keyCipher = Cipher.getInstance(PK_CIPHER);
        keyCipher.init(Cipher.ENCRYPT_MODE, pk);

        String base64Key = encryptKey(keyCipher, encryptionCipher, secKey);
        String base64Message = encryptMessage(message, encryptionCipher);

        return base64Key + ":" + base64Message;
    }

    /**
     * Read a pair of public/private keys from the given directory and with the given base name. If
     * the keys aren't present a new pair of keys will be generated and written to the directory.
     * 
     * @param directory the directory where the files should be
     * @param baseName the base name (filename without file type)
     * @return the pair of keys
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws IOException
     */
    public static KeyPair getKeyPair(Path directory, String baseName)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        // try to get around "creative" naming creating security problems
        Path basePath = Path.of(baseName).getFileName();

        if (keyFilesExist(directory, basePath)) {
            return readKeyPair(directory, basePath);
        }
        else {
            return generateKeyPair(directory, basePath);
        }
    }

    /**
     * Read all public keys in the given directory (and subdirectories) and return them in a map.
     * 
     * The method assumes that keys are named <name>.pub and <name> will be the key in the hash map.
     * If multiples files (in different directories) have the same name, it will be undefined which
     * one that will be put into the map.
     * 
     * @param directory the directory to search for public keys
     * @return a map of names to public keys
     * 
     * @throws IOException
     */
    public static Map<String, PublicKey> readPublicKeys(Path directory) throws IOException {
        validateDirectory(directory);

        try (Stream<Path> files = Files.walk(directory, 1)) {
            return files.filter(p -> p.toString().endsWith(".pub")).filter(Files::isRegularFile)
                    .filter(Files::isReadable).collect(mapCollector());
        }
    }

    public static String sign(String message, PrivateKey pk)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        byte[] secretMessageBytes = message.getBytes(StandardCharsets.UTF_8);

        Signature sig = Signature.getInstance(SIGNATURE_CIPHER);
        sig.initSign(pk);
        sig.update(secretMessageBytes);

        Encoder encoder = Base64.getEncoder();

        return encoder.encodeToString(sig.sign());
    }

    public static boolean verify(String message, String signature, PublicKey pk)
            throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
        Signature sig = Signature.getInstance(SIGNATURE_CIPHER);
        sig.initVerify(pk);
        sig.update(message.getBytes(StandardCharsets.UTF_8));

        return sig.verify(Base64.getDecoder().decode(signature));
    }

    private static String encryptKey(Cipher toEncryptWith, Cipher toBeEncrypted, SecretKey key)
            throws IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException {

        // Create a byte buffer looking like:
        // <tlen><iv length><iv><sec key>

        // it includes the IV length to make this format a bit more flexible

        ByteBuffer intBuff = ByteBuffer.allocate(8);

        int tlen = toBeEncrypted.getParameters().getParameterSpec(GCMParameterSpec.class).getTLen();
        byte[] iv = toBeEncrypted.getIV();

        intBuff.putInt(tlen);
        intBuff.putInt(iv.length);

        toEncryptWith.update(intBuff.array());
        toEncryptWith.update(iv);

        byte[] encryptedKey = toEncryptWith.doFinal(key.getEncoded());
        return Base64.getEncoder().encodeToString(encryptedKey);
    }

    private static String encryptMessage(String message, Cipher encryptionCipher)
            throws IllegalBlockSizeException, BadPaddingException {
        byte[] secretMessageBytes = message.getBytes(StandardCharsets.UTF_8);
        byte[] encryptedMessageBytes = encryptionCipher.doFinal(secretMessageBytes);
        return Base64.getEncoder().encodeToString(encryptedMessageBytes);
    }

    private static KeyPair generateKeyPair(Path directory, Path baseName)
            throws IOException, NoSuchAlgorithmException {
        validateDirectory(directory);
        validateNotNull(baseName);

        KeyPairGenerator generator = KeyPairGenerator.getInstance(PK_KEY_TYPE);
        generator.initialize(4096);

        KeyPair pair = generator.generateKeyPair();

        PrivateKey privateKey = pair.getPrivate();
        PublicKey publicKey = pair.getPublic();

        Path publicKeyPath = directory.resolve(baseName + PUBLIC_KEY_SUFFIX);
        try (OutputStream fos = Files.newOutputStream(publicKeyPath)) {
            fos.write(publicKey.getEncoded());
        }

        Path privateKeyPath = directory.resolve(baseName + PRIVATE_KEY_SUFFIX);
        try (OutputStream fos = Files.newOutputStream(privateKeyPath)) {
            fos.write(privateKey.getEncoded());
        }

        return pair;
    }

    private static KeyPair readKeyPair(Path directory, Path baseName)
            throws NoSuchAlgorithmException, InvalidKeySpecException, IOException {
        validateDirectory(directory);
        validateNotNull(baseName);

        PublicKey oPubKey = readPublicKey(directory.resolve(baseName + PUBLIC_KEY_SUFFIX));
        PrivateKey oPrivKey = readPrivateKey(directory.resolve(baseName + PRIVATE_KEY_SUFFIX));

        return new KeyPair(oPubKey, oPrivKey);
    }

    private static PrivateKey readPrivateKey(Path path)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        validateIsReadable(path);

        byte[] privateKeyBytes = Files.readAllBytes(path);

        KeyFactory keyFactory = KeyFactory.getInstance(PK_KEY_TYPE);
        EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);

        return keyFactory.generatePrivate(privateKeySpec);
    }

    private static PublicKey readPublicKey(Path path)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        validateIsReadable(path);

        byte[] publicKeyBytes = Files.readAllBytes(path);

        KeyFactory keyFactory = KeyFactory.getInstance(PK_KEY_TYPE);
        EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);

        return keyFactory.generatePublic(publicKeySpec);
    }

    @SuppressWarnings("java:S112")
    private static Collector<Path, ?, Map<String, PublicKey>> mapCollector() {
        return Collectors.toMap(path -> {
            String fileName = path.getFileName().toString();
            return fileName.substring(0, fileName.lastIndexOf("."));
        }, path -> {
            try {
                return readPublicKey(path);
            }
            catch (IOException | NoSuchAlgorithmException | InvalidKeySpecException ex) {
                throw new RuntimeException(ex);
            }
        });
    }

    private static boolean keyFilesExist(Path directory, Path baseName) {
        Path pubKeyPath = directory.resolve(baseName + PUBLIC_KEY_SUFFIX);
        Path priKeyPath = directory.resolve(baseName + PRIVATE_KEY_SUFFIX);

        return Files.isReadable(pubKeyPath) && Files.isReadable(priKeyPath);
    }

    private static void validateDirectory(Path directory) {
        if (directory == null || !Files.isDirectory(directory)) {
            throw new IllegalArgumentException("argument not a directory");
        }
    }

    private static void validateIsReadable(Path path) {
        if (path == null || !Files.isReadable(path)) {
            throw new IllegalArgumentException("argument not a directory");
        }
    }

    private static <T> void validateNotNull(T obj) {
        if (obj == null) {
            throw new IllegalArgumentException("argument must not be null");
        }
    }
}
