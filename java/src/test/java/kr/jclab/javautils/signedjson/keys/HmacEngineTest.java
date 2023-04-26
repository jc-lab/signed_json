package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.Signer;
import kr.jclab.javautils.signedjson.Verifier;
import kr.jclab.javautils.signedjson.model.SignedJson;
import kr.jclab.javautils.signedjson.model.SignedJsonSignature;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class HmacEngineTest {
    private final HmacEngine engine = new HmacEngine();
    private final byte[] SAMPLE_KEY = "hello".getBytes(StandardCharsets.UTF_8);

    @Test
    void getSchema() {
        assertThat(engine.getSchema()).isEqualTo("hmac");
    }

    @Test
    void newSigner() {
        Signer signer = engine.newSigner(sampleKey());
        assertThat(signer).isNotNull();
    }

    @Test
    void newVerifier() {
        Verifier verifier = engine.newVerifier(sampleKey());
        assertThat(verifier).isNotNull();
    }

    @Test
    void getKeyId() {
        PublicKey publicKey = sampleKey();
        String keyId = engine.getKeyId(publicKey);
        assertThat(keyId).isEqualTo("test");
    }

    @Test
    void signAndVerify() {
        HmacKey sampleKey = sampleKey();

        TestMessage testMessage = new TestMessage();
        testMessage.hello = "WORLD";
        SignedJson<TestMessage> signedJson = SignedJson.<TestMessage>builder()
                .signed(testMessage)
                .build();

        engine.newSigner(sampleKey).signJson(signedJson);
        assertThat(signedJson.getSignatures()).hasSize(1);

        assertThat(engine.newVerifier(sampleKey).verifyJson(signedJson)).isTrue();
    }

    @Test
    void verifyJson() {
        PublicKey publicKey = sampleKey();

        TestMessage testMessage = new TestMessage();
        testMessage.hello = "WORLD";

        SignedJson<TestMessage> signedJson = SignedJson.<TestMessage>builder()
                .signed(testMessage)
                .signatures(Collections.singletonList(
                        SignedJsonSignature.builder()
                                .keyid("test")
                                .sig("ue270d4MoQpyP9Qer-WBBRTuVsYpDVVCPid7uFIj4Ek")
                                .build()
                ))
                .build();

        Verifier verifier = engine.newVerifier(publicKey);
        assertThat(verifier.verifyJson(signedJson)).isTrue();

        testMessage.hello = "xxxxx";
        assertThat(verifier.verifyJson(signedJson)).isFalse();
    }

    HmacKey sampleKey() {
        return new HmacKey("SHA256", "test", SAMPLE_KEY);
    }
}