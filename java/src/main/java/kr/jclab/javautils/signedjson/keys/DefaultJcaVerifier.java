package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.KeyEngine;

import java.security.*;

public class DefaultJcaVerifier extends AbstractVerifier {
    private final KeyEngine engine;
    private final PublicKey publicKey;
    private final SignatureSupplier signatureSupplier;

    public DefaultJcaVerifier(KeyEngine engine, PublicKey publicKey, SignatureSupplier signatureSupplier) {
        this.engine = engine;
        this.publicKey = publicKey;
        this.signatureSupplier = signatureSupplier;
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
            Signature signature = this.signatureSupplier.newInstance();
            signature.initVerify(this.publicKey);
            signature.update(data);
            return signature.verify(sig);
        } catch (NoSuchAlgorithmException | InvalidKeyException e) {
            throw new RuntimeException(e);
        } catch (SignatureException e) {
            return false;
        }
    }

    @FunctionalInterface
    public interface SignatureSupplier {
        Signature newInstance() throws NoSuchAlgorithmException;
    }
}
