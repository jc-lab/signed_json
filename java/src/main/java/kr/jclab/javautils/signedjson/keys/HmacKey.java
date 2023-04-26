package kr.jclab.javautils.signedjson.keys;

import lombok.Getter;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.DestroyFailedException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;

public class HmacKey extends SecretKeySpec implements PublicKey, PrivateKey {
    private final String algorithm;
    @Getter
    private final String keyId;
    @Getter
    private final byte[] raw;
    private boolean destroyed = false;

    /**
     * initialize
     *
     * @param algorithm SHA256
     * @param raw raw key
     */
    public HmacKey(String algorithm, String keyId, byte[] raw) {
        super(raw, algorithm);
        this.algorithm = algorithm;
        this.keyId = keyId;
        this.raw = raw;
    }

    @Override
    public String getAlgorithm() {
        return algorithm;
    }

    @Override
    public String getFormat() {
        return "hmac";
    }

    @Override
    public byte[] getEncoded() {
        return raw;
    }

    @Override
    public void destroy() throws DestroyFailedException {
        Arrays.fill(raw, (byte) 0);
        this.destroyed = true;
    }

    @Override
    public boolean isDestroyed() {
        return destroyed;
    }
}
