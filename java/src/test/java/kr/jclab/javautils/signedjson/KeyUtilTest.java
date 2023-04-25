package kr.jclab.javautils.signedjson;

import org.bouncycastle.openpgp.PGPException;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.security.PublicKey;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class KeyUtilTest {
    @Test
    void readPublicKeyFromPem_ed25519_x509() throws PGPException, IOException {
        KeyUtil.PublicKeyWithEngine result = KeyUtil.readPublicKeyFromText("-----BEGIN PUBLIC KEY-----\n" +
                "MCowBQYDK2VwAyEAUUdn1S3fv+nFKKQn7f9lCcEDuGDDr6sgUoEZ5tKSOFk=\n" +
                "-----END PUBLIC KEY-----");
        assertThat(result.getEngine().getSchema()).isEqualTo("ed25519");
        assertThat(result.getPublicKey()).isInstanceOf(PublicKey.class);
    }

    @Test
    void readPublicKeyFromArmor() throws PGPException, IOException {
        KeyUtil.PublicKeyWithEngine result = KeyUtil.readPublicKeyFromText("-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: User-ID:\ttest-rsa <test-rsa@example.com>\nComment: Created:\t23. 4. 24. 오후 12:21\nComment: Expires:\t25. 4. 24. 오후 12:00\nComment: Type:\t3,072-bit RSA (secret key available)\nComment: Usage:\tSigning, Encryption, Certifying User-IDs\nComment: Fingerprint:\t5458C996903C6DB3AEFA377A8314B42600D3D966\n\n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\nVVxYfsf6LULHjZBok6oROZ4FKgfCz1k=\n=lSR3\n-----END PGP PUBLIC KEY BLOCK-----\n");
        assertThat(result.getEngine().getSchema()).isEqualTo("pgp");
        assertThat(result.getPublicKey()).isInstanceOf(PublicKey.class);
    }
}