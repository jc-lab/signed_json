package kr.jclab.javautils.signedjson;

import kr.jclab.javautils.signedjson.exception.InvalidKeyException;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface KeyEngine {
    String getSchema();
    String marshalPublicKey(PublicKey publicKey) throws InvalidKeyException;
    PublicKey unmarshalPublicKey(String input) throws InvalidKeyException;
    Signer newSigner(PrivateKey privateKey) throws InvalidKeyException;
    Verifier newVerifier(PublicKey publicKey) throws InvalidKeyException;
    String getKeyId(PublicKey publicKey);

    static KeyEngine getEngine(String schema) {
        return StaticHolder.getEngine(schema);
    }
}
