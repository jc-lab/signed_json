package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.KeyEngine;
import kr.jclab.javautils.signedjson.StaticHolder;
import kr.jclab.javautils.signedjson.Verifier;
import kr.jclab.javautils.signedjson.exception.InvalidKeyException;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;

public class PgpEngine implements KeyEngine {
    @Override
    public String getSchema() {
        return "pgp";
    }

    @Override
    public PublicKey unmarshalPublicKey(String input) {
        if (input.startsWith("-----")) {
            JcaPGPPublicKeyRingCollection collection;
            try (ArmoredInputStream inputStream = new ArmoredInputStream(new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)))) {
                collection = new JcaPGPPublicKeyRingCollection(inputStream);
            } catch (IOException | PGPException e) {
                throw new RuntimeException(e);
            }
            PGPPublicKeyRing keyRing = collection.iterator().next();
            return new PgpPublicKey(keyRing);
        }
        return null;
    }

    @Override
    public Verifier newVerifier(PublicKey publicKey) {
        PgpPublicKey pgpPublicKey = toPgpPublicKey(publicKey);
        return new PgpVerifier(this, pgpPublicKey);
    }

    @Override
    public String getKeyId(PublicKey publicKey) {
        PgpPublicKey pgpPublicKey = toPgpPublicKey(publicKey);
        return StaticHolder.getEncoder().encodeToString(pgpPublicKey.getKeyRing().getPublicKey().getFingerprint());
    }

    static PgpPublicKey toPgpPublicKey(PublicKey publicKey) {
        if (!(publicKey instanceof PgpPublicKey)) {
            throw new InvalidKeyException("unknown class: " + publicKey.getClass().getName());
        }
        return (PgpPublicKey) publicKey;
    }
}
