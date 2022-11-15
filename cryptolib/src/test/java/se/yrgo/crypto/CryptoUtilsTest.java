package se.yrgo.crypto;

import static org.assertj.core.api.Assertions.*;
import static org.junit.jupiter.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.nio.file.FileSystem;
import java.security.*;
import java.security.spec.*;
import java.util.*;
import javax.crypto.*;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.*;
import org.junit.jupiter.params.provider.*;
import com.github.marschall.memoryfilesystem.*;

class CryptoUtilsTest {
    private static FileSystem fs;
    private static KeyPair alice;
    private static KeyPair bob;

    @BeforeAll
    static void setup() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        fs = MemoryFileSystemBuilder.newEmpty().build();
        Path rootDir = fs.getRootDirectories().iterator().next();
        alice = CryptoUtils.getKeyPair(rootDir, "alice");
        bob = CryptoUtils.getKeyPair(rootDir, "bob");
    }

    @AfterAll
    static void tearDown() throws IOException {
        fs.close();
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "abc def ghi", "!\"#¤%&/()=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"})
    void encodeThenDecode(String message) throws InvalidKeyException, NoSuchAlgorithmException,
            NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException,
            InvalidParameterSpecException, InvalidAlgorithmParameterException {
        String encrypted = CryptoUtils.encrypt(message, alice.getPublic());
        String decrypted = CryptoUtils.decrypt(encrypted, alice.getPrivate());
        assertThat(decrypted).isEqualTo(message);
    }

    @ParameterizedTest
    @ValueSource(strings = {"a", "abc def ghi", "!\"#¤%&/()=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"})
    void encodeThenDecodeWithSign(String message) throws InvalidKeyException,
            NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException,
            BadPaddingException, InvalidParameterSpecException, InvalidAlgorithmParameterException,
            SignatureException, InvalidKeySpecException, IOException {
        String encrypted = CryptoUtils.encryptAndSign(message, bob.getPublic(), alice.getPrivate());
        Optional<String> decrypted =
                CryptoUtils.decryptAndVerify(encrypted, bob.getPrivate(), alice.getPublic());

        assertThat(decrypted).isNotEmpty().hasValue(message);
    }

    @Test
    void wrongDecrypt() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException,
            InvalidAlgorithmParameterException, SignatureException, InvalidKeySpecException,
            IOException {
        String message = "some old message";

        String encrypted = CryptoUtils.encryptAndSign(message, bob.getPublic(), alice.getPrivate());

        assertThrows(GeneralSecurityException.class, () ->
                CryptoUtils.decryptAndVerify(encrypted, alice.getPrivate(), alice.getPublic()));
    }

    @Test
    void wrongSign() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException,
            IllegalBlockSizeException, BadPaddingException, InvalidParameterSpecException,
            InvalidAlgorithmParameterException, SignatureException, InvalidKeySpecException,
            IOException {
        String message = "some old message";

        String encrypted = CryptoUtils.encryptAndSign(message, bob.getPublic(), alice.getPrivate());
        Optional<String> decrypted =
                CryptoUtils.decryptAndVerify(encrypted, bob.getPrivate(), bob.getPublic());

        assertThat(decrypted).isEmpty();
    }
}
