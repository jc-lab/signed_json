package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.KeyEngine;
import kr.jclab.javautils.signedjson.StaticHolder;
import kr.jclab.javautils.signedjson.Verifier;
import kr.jclab.javautils.signedjson.exception.InvalidKeyException;
import org.bouncycastle.bcpg.ArmoredInputStream;
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
    public String marshalPublicKey(PublicKey publicKey) throws InvalidKeyException {
        PgpPublicKey pgpPublicKey = toPgpPublicKey(publicKey);
        try {
            return StaticHolder.getEncoder().encodeToString(pgpPublicKey.getKeyRing().getEncoded());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public PublicKey unmarshalPublicKey(String input) {
        JcaPGPPublicKeyRingCollection collection = null;

        if (input.startsWith("-----")) {
            try (ArmoredInputStream inputStream = new ArmoredInputStream(new ByteArrayInputStream(input.getBytes(StandardCharsets.UTF_8)))) {
                collection = new JcaPGPPublicKeyRingCollection(inputStream);
            } catch (IOException | PGPException e) {
                throw new RuntimeException(e);
            }
        } else {
            byte[] raw = StaticHolder.getDecoder().decode(input);
            try (ByteArrayInputStream inputStream = new ByteArrayInputStream(raw)) {
                collection = new JcaPGPPublicKeyRingCollection(inputStream);
            } catch (IOException | PGPException e) {
                throw new RuntimeException(e);
            }
        }

        if (collection == null) {
            throw new InvalidKeyException("unknown key format");
        }

        PGPPublicKeyRing keyRing = collection.iterator().next();
        return new PgpPublicKey(keyRing);
    }

    @Override
    public Verifier newVerifier(PublicKey publicKey) throws InvalidKeyException {
        PgpPublicKey pgpPublicKey = toPgpPublicKey(publicKey);
        return new PgpVerifier(this, pgpPublicKey);
    }

    @Override
    public String getKeyId(PublicKey publicKey) {
        PgpPublicKey pgpPublicKey = toPgpPublicKey(publicKey);
        return StaticHolder.getEncoder().encodeToString(pgpPublicKey.getKeyRing().getPublicKey().getFingerprint());
    }

    static PgpPublicKey toPgpPublicKey(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof PgpPublicKey)) {
            throw new InvalidKeyException("unknown class: " + publicKey.getClass().getName());
        }
        return (PgpPublicKey) publicKey;
    }
}
