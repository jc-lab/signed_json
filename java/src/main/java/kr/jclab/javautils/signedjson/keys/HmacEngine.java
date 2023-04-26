package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.KeyEngine;
import kr.jclab.javautils.signedjson.Signer;
import kr.jclab.javautils.signedjson.StaticHolder;
import kr.jclab.javautils.signedjson.Verifier;
import kr.jclab.javautils.signedjson.exception.InvalidKeyException;
import kr.jclab.javautils.signedjson.util.HashUtil;

import javax.crypto.Mac;
import java.security.*;

public class HmacEngine implements KeyEngine {
    @Override
    public String getSchema() {
        return "hmac";
    }

    @Override
    public String marshalPublicKey(PublicKey publicKey) throws InvalidKeyException {
        throw new InvalidKeyException("no public key");
    }

    @Override
    public PublicKey unmarshalPublicKey(String input) throws InvalidKeyException {
        throw new InvalidKeyException("no public key");
    }

    @Override
    public Verifier newVerifier(PublicKey publicKey) throws InvalidKeyException {
        HmacKey hmacKey = toHmacKey(publicKey);
        try {
            Mac.getInstance(signatureName(hmacKey), StaticHolder.getBcProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return new DefaultJcaMacVerifier(this, publicKey, () -> Mac.getInstance(signatureName(hmacKey), StaticHolder.getBcProvider()));
    }

    @Override
    public Signer newSigner(PrivateKey privateKey) throws InvalidKeyException {
        HmacKey hmacKey = toHmacKey(privateKey);
        try {
            Mac.getInstance(signatureName(hmacKey), StaticHolder.getBcProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return new DefaultJcaMacSigner(this, hmacKey, hmacKey, () -> Mac.getInstance(signatureName(hmacKey), StaticHolder.getBcProvider()));
    }

    @Override
    public String getKeyId(PublicKey publicKey) {
        HmacKey hmacKey = toHmacKey(publicKey);
        return hmacKey.getKeyId();
    }

    static HmacKey toHmacKey(Key key) throws InvalidKeyException {
        if (!(key instanceof HmacKey)) {
            throw new InvalidKeyException("unknown class: " + key.getClass().getName());
        }
        return (HmacKey) key;
    }

    static String signatureName(HmacKey key) {
        return "HMAC" + key.getAlgorithm();
    }
}
