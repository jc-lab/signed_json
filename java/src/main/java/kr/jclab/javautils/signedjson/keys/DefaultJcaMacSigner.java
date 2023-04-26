package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.KeyEngine;

import javax.crypto.Mac;
import java.security.*;

public class DefaultJcaMacSigner extends AbstractSigner {
    private final KeyEngine engine;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final MacSupplier macSupplier;

    public DefaultJcaMacSigner(KeyEngine engine, PrivateKey privateKey, PublicKey publicKey, MacSupplier macSupplier) {
        this.engine = engine;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.macSupplier = macSupplier;
    }

    @Override
    public PrivateKey getPrivateKey() {
        return this.privateKey;
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
    public byte[] signMessage(byte[] data) {
        try {
            Mac signature = this.macSupplier.newInstance();
            signature.init(this.privateKey);
            signature.update(data);
            return signature.doFinal();
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        }
    }

    @FunctionalInterface
    public interface MacSupplier {
        Mac newInstance() throws NoSuchAlgorithmException;
    }
}
