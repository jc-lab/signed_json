package kr.jclab.javautils.signedjson;

import kr.jclab.javautils.signedjson.exception.InvalidKeyException;

import java.security.PublicKey;

public interface KeyEngine {
    String getSchema();
    PublicKey unmarshalPublicKey(String input) throws InvalidKeyException;
    Verifier newVerifier(PublicKey publicKey);
    String getKeyId(PublicKey publicKey);

    static KeyEngine getEngine(String schema) {
        return StaticHolder.getEngine(schema);
    }
}
