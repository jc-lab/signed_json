package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.KeyEngine;

import java.security.*;

public class DefaultJcaSigner extends AbstractSigner {
    private final KeyEngine engine;
    private final PrivateKey privateKey;
    private final PublicKey publicKey;
    private final SignatureSupplier signatureSupplier;

    public DefaultJcaSigner(KeyEngine engine, PrivateKey privateKey, PublicKey publicKey, SignatureSupplier signatureSupplier) {
        this.engine = engine;
        this.privateKey = privateKey;
        this.publicKey = publicKey;
        this.signatureSupplier = signatureSupplier;
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
            Signature signature = this.signatureSupplier.newInstance();
            signature.initSign(this.privateKey);
            signature.update(data);
            return signature.sign();
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new RuntimeException(e);
        }
    }

    @FunctionalInterface
    public interface SignatureSupplier {
        Signature newInstance() throws NoSuchAlgorithmException;
    }
}
