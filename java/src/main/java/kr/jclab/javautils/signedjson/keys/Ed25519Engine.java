package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.KeyEngine;
import kr.jclab.javautils.signedjson.Signer;
import kr.jclab.javautils.signedjson.StaticHolder;
import kr.jclab.javautils.signedjson.Verifier;
import kr.jclab.javautils.signedjson.exception.InvalidKeyException;
import kr.jclab.javautils.signedjson.util.HashUtil;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.bouncycastle.jcajce.spec.RawEncodedKeySpec;
import org.bouncycastle.math.ec.rfc8032.Ed25519;

import java.security.*;

public class Ed25519Engine implements KeyEngine {
    @Override
    public String getSchema() {
        return "ed25519";
    }

    @Override
    public String marshalPublicKey(PublicKey publicKey) throws InvalidKeyException {
        BCEdDSAPublicKey edPublicKey = toBCEdDSAPublicKey(publicKey);
        return StaticHolder.getEncoder().encodeToString(edPublicKey.getPointEncoding());
    }

    @Override
    public PublicKey unmarshalPublicKey(String input) throws InvalidKeyException {
        byte[] rawKey = StaticHolder.getDecoder().decode(input);
        if (!Ed25519.validatePublicKeyFull(rawKey, 0)) {
            throw new InvalidKeyException("invalid public key");
        }
        try {
            KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", StaticHolder.getBcProvider());
            return keyFactory.generatePublic(new RawEncodedKeySpec(rawKey));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Override
    public Signer newSigner(PrivateKey privateKey) throws InvalidKeyException {
        BCEdDSAPrivateKey bcPrivateKey = toBCEdDSAPrivateKey(privateKey);
        try {
            Signature.getInstance("Ed25519", StaticHolder.getBcProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return new DefaultJcaSigner(this, privateKey, bcPrivateKey.getPublicKey(), () -> Signature.getInstance("Ed25519", StaticHolder.getBcProvider()));
    }

    @Override
    public Verifier newVerifier(PublicKey publicKey) throws InvalidKeyException {
        toBCEdDSAPublicKey(publicKey);
        try {
            Signature.getInstance("Ed25519", StaticHolder.getBcProvider());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
        return new DefaultJcaVerifier(this, publicKey, () -> Signature.getInstance("Ed25519", StaticHolder.getBcProvider()));
    }

    @Override
    public String getKeyId(PublicKey publicKey) {
        BCEdDSAPublicKey edPublicKey = toBCEdDSAPublicKey(publicKey);
        return HashUtil.sha256Encode(edPublicKey.getPointEncoding());
    }

    static BCEdDSAPublicKey toBCEdDSAPublicKey(PublicKey publicKey) throws InvalidKeyException {
        if (!(publicKey instanceof BCEdDSAPublicKey)) {
            throw new InvalidKeyException("unknown class: " + publicKey.getClass().getName());
        }
        return (BCEdDSAPublicKey) publicKey;
    }

    static BCEdDSAPrivateKey toBCEdDSAPrivateKey(PrivateKey privateKey) throws InvalidKeyException {
        if (!(privateKey instanceof BCEdDSAPrivateKey)) {
            throw new InvalidKeyException("unknown class: " + privateKey.getClass().getName());
        }
        return (BCEdDSAPrivateKey) privateKey;
    }
}
