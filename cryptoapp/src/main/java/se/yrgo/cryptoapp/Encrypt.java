package se.yrgo.cryptoapp;

import java.io.*;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import se.yrgo.crypto.*;

public class Encrypt {
    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidKeySpecException,
            IOException {
        KeyPair pair = CryptoUtils.getKeyPair(Path.of("."), "CHANGE_ME");
        // encrypt message
        // print encrypted message
        // decrypt message
        // print decrypted message
    }
}
