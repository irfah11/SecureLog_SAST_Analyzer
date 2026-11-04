import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

// Source-only fixture. No main method; upload to the scanner, do not deploy.
// Caller must securely supply the key and fresh, unique GCM parameters per record.
public class CompleteJavaLogging {
    public interface RequestSource { String getRemoteAddr(); }

    static boolean isAuthenticated(boolean result) { return result; }

    public static boolean login(boolean authenticated, String username,
            RequestSource request, SecretKey key, GCMParameterSpec parameters) throws Exception {
        if (!isAuthenticated(authenticated)) {
            Map<String, String> record = Map.of(
                "timestamp", Instant.now().toString(),
                "event", "LOGIN_FAILED",
                "claimed_identity", username,
                "actor_type", "unauthenticated",
                "source_ip", request.getRemoteAddr(),
                "result", "FAILURE",
                "reason", "INVALID_CREDENTIALS"
            );
            byte[] plaintext = record.toString().getBytes(StandardCharsets.UTF_8);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key, parameters);
            byte[] encrypted = cipher.doFinal(plaintext);
            String payload = Base64.getEncoder().encodeToString(encrypted);
            Files.writeString(Path.of("security.txt"), payload,
                StandardOpenOption.CREATE, StandardOpenOption.APPEND);
            return false;
        }
        return true;
    }
}
