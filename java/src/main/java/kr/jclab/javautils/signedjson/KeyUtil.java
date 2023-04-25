package kr.jclab.javautils.signedjson;

import kr.jclab.javautils.signedjson.exception.InvalidKeyException;
import kr.jclab.javautils.signedjson.keys.PgpEngine;
import kr.jclab.javautils.signedjson.keys.PgpPublicKey;
import lombok.AllArgsConstructor;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.bcpg.ArmoredInputStream;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.jcajce.JcaPGPPublicKeyRingCollection;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

public class KeyUtil {
    public static PublicKeyWithEngine readPublicKeyFromPem(String pem) throws IOException {
        try (PemReader pemReader = new PemReader(new StringReader(pem))) {
            PemObject pemObject = pemReader.readPemObject();
            if ("PUBLIC KEY".equalsIgnoreCase(pemObject.getType())) {
                SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(pemObject.getContent());
                String algorithmOid = subjectPublicKeyInfo.getAlgorithm().getAlgorithm().toString();
                if ("1.3.101.112".equals(algorithmOid)) {
                    KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", StaticHolder.getBcProvider());
                    PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(pemObject.getContent()));
                    return new PublicKeyWithEngine(
                            KeyEngine.getEngine("ed25519"),
                            publicKey
                    );
                }

                throw new InvalidKeyException("unknown algorithm: " + algorithmOid);
            }

            throw new InvalidKeyException("unknown type: " + pemObject.getType());
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKeyWithEngine readPublicKeyFromArmor(String armor) throws IOException, PGPException {
        try (ArmoredInputStream inputStream = new ArmoredInputStream(new ByteArrayInputStream(armor.getBytes(StandardCharsets.UTF_8)))) {
            JcaPGPPublicKeyRingCollection collection = new JcaPGPPublicKeyRingCollection(inputStream);
            PGPPublicKeyRing keyRing = collection.iterator().next();
            PgpEngine engine = (PgpEngine) KeyEngine.getEngine("pgp");
            return new PublicKeyWithEngine(
                    engine,
                    new PgpPublicKey(keyRing)
            );
        }
    }

    public static PublicKeyWithEngine readPublicKeyFromText(String input) throws IOException, PGPException {
        input = input.trim();
        if (input.startsWith("-----BEGIN PGP")) {
            return readPublicKeyFromArmor(input);
        } else if (input.startsWith("-----BEGIN")) {
            return readPublicKeyFromPem(input);
        }
        throw new IOException("unknown format");
    }

    @Getter
    @ToString
    @EqualsAndHashCode
    @AllArgsConstructor
    public static class PublicKeyWithEngine {
        private final KeyEngine engine;
        private final PublicKey publicKey;
    }
}
