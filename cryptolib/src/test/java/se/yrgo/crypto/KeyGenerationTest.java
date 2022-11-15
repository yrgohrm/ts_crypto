package se.yrgo.crypto;

import static org.assertj.core.api.Assertions.*;
import java.io.*;
import java.nio.file.*;
import java.nio.file.FileSystem;
import java.util.stream.*;
import org.junit.jupiter.api.*;
import com.github.marschall.memoryfilesystem.*;

class KeyGenerationTest {
    private FileSystem fs;

    @BeforeEach
    void setup() throws IOException {
        fs = MemoryFileSystemBuilder.newEmpty().build();
    }

    @AfterEach
    void tearDown() throws IOException {
        fs.close();
    }

    @Test
    void generateKeys() throws Exception {
        Path dir = fs.getRootDirectories().iterator().next();
        CryptoUtils.getKeyPair(dir, "test");
        var list = Files.walk(dir).collect(Collectors.toList());
        assertThat(list).hasSize(3);
    }


}
