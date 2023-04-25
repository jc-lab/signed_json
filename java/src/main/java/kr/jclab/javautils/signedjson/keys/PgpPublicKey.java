package kr.jclab.javautils.signedjson.keys;

import lombok.Getter;
import org.bouncycastle.openpgp.PGPPublicKeyRing;

import java.security.PublicKey;

public class PgpPublicKey implements PublicKey {
    @Getter
    private final PGPPublicKeyRing keyRing;

    public PgpPublicKey(PGPPublicKeyRing keyRing) {
        this.keyRing = keyRing;
    }

    @Override
    public String getAlgorithm() {
        return null;
    }

    @Override
    public String getFormat() {
        return null;
    }

    @Override
    public byte[] getEncoded() {
        return new byte[0];
    }
}
