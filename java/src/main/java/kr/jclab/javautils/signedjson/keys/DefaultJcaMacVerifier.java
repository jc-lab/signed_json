package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.KeyEngine;

import javax.crypto.Mac;
import java.security.*;
import java.util.Arrays;

public class DefaultJcaMacVerifier extends AbstractVerifier {
    private final KeyEngine engine;
    private final PublicKey publicKey;
    private final MacSupplier macSupplier;

    public DefaultJcaMacVerifier(KeyEngine engine, PublicKey publicKey, MacSupplier macSupplier) {
        this.engine = engine;
        this.publicKey = publicKey;
        this.macSupplier = macSupplier;
    }

    @Override
    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    @Override
    public String getKeyId() {
        return this.engine.getKeyId(this.publicKey);
    }

    @Override
    public boolean verifyMessage(byte[] data, byte[] sig) {
        try {
            Mac signature = this.macSupplier.newInstance();
            signature.init(this.publicKey);
            signature.update(data);
            byte[] computed = signature.doFinal();
            return Arrays.equals(sig, computed);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @FunctionalInterface
    public interface MacSupplier {
        Mac newInstance() throws NoSuchAlgorithmException;
    }
}
