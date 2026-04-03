package org.corazawaf.coraza.internal;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

/**
 * Loads the native coraza JNI library.
 *
 * <p>In production (fat JAR) the library is extracted from the JAR resources to
 * a temporary directory and loaded from there. A shutdown hook cleans it up.
 *
 * <p>In test mode (system property {@code coraza.native.dir} set by Surefire) the
 * library is loaded directly from the build output directory via
 * {@link System#load(String)}.
 */
public final class NativeLoader {

    private NativeLoader() {}

    public static synchronized void load() {
        // Test mode: Surefire sets coraza.native.dir to target/native
        String nativeDir = System.getProperty("coraza.native.dir");
        if (nativeDir != null) {
            loadFromDirectory(nativeDir);
            return;
        }

        // Production mode: extract from JAR resources
        String resourcePath = resourcePath();
        try (InputStream in = NativeLoader.class.getResourceAsStream(resourcePath)) {
            if (in == null) {
                throw new UnsatisfiedLinkError(
                        "Native library not found in JAR: " + resourcePath);
            }
            Path tmp = extractToTemp(in, libFilename());
            System.load(tmp.toAbsolutePath().toString());
        } catch (IOException e) {
            throw new UnsatisfiedLinkError("Failed to extract native library: " + e.getMessage());
        }
    }

    // ------------------------------------------------------------------

    private static void loadFromDirectory(String dir) {
        String filename = libFilename();
        Path path = Path.of(dir).resolve(filename);
        if (!Files.exists(path)) {
            throw new UnsatisfiedLinkError("Native library not found: " + path);
        }
        System.load(path.toAbsolutePath().toString());
    }

    private static String resourcePath() {
        return "/org/corazawaf/coraza/native/" + platformKey() + "/" + libFilename();
    }

    private static String libFilename() {
        String os = System.getProperty("os.name", "").toLowerCase();
        if (os.contains("mac") || os.contains("darwin")) {
            return "libcoraza_jni.dylib";
        }
        return "libcoraza_jni.so";
    }

    private static String platformKey() {
        String os = System.getProperty("os.name", "").toLowerCase();
        String arch = System.getProperty("os.arch", "").toLowerCase();
        String osKey = (os.contains("mac") || os.contains("darwin")) ? "mac" : "linux";
        String archKey = arch.contains("aarch64") || arch.contains("arm64") ? "aarch64" : "x86_64";
        return osKey + "-" + archKey;
    }

    private static Path extractToTemp(InputStream in, String filename) throws IOException {
        // Try system temp first; fall back to home cache if noexec.
        Path dir;
        try {
            dir = Files.createTempDirectory("coraza-native-");
        } catch (IOException e) {
            dir = Path.of(System.getProperty("user.home"), ".cache", "coraza-native");
            Files.createDirectories(dir);
        }

        Path dest = dir.resolve(filename);
        try (OutputStream out = Files.newOutputStream(dest, StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING)) {
            in.transferTo(out);
        }
        dest.toFile().setExecutable(true);

        Path finalDest = dest;
        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            try { Files.deleteIfExists(finalDest); } catch (IOException ignored) {}
        }));

        return dest;
    }
}
