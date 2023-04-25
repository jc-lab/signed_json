package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.Verifier;
import kr.jclab.javautils.signedjson.model.SignedJson;
import kr.jclab.javautils.signedjson.model.SignedJsonSignature;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;

class Ed25519EngineTest {
    private final Ed25519Engine engine = new Ed25519Engine();

    @Test
    void getSchema() {
        assertThat(engine.getSchema()).isEqualTo("ed25519");
    }

    @Test
    void unmarshalPublicKey() {
        PublicKey publicKey = samplePublicKey();
        assertThat(publicKey).isNotNull().isOfAnyClassIn(BCEdDSAPublicKey.class, PublicKey.class);
    }

    @Test
    void newVerifier() {
        Verifier verifier = engine.newVerifier(samplePublicKey());
        assertThat(verifier).isNotNull();
    }

    @Test
    void getKeyId() {
        PublicKey publicKey = samplePublicKey();
        String keyId = engine.getKeyId(publicKey);
        assertThat(keyId).isEqualTo("EUC_wk4IQSWkp2QFLzUWXQIFt_3R3oMa2O8fzNpfuzU");
    }

    @Test
    void verifyJson() {
        PublicKey publicKey = samplePublicKey();

        TestMessage testMessage = new TestMessage();
        testMessage.hello = "WORLD";

        SignedJson<TestMessage> signedJson = SignedJson.<TestMessage>builder()
                .signed(testMessage)
                .signatures(Collections.singletonList(
                        SignedJsonSignature.builder()
                                .keyid("EUC_wk4IQSWkp2QFLzUWXQIFt_3R3oMa2O8fzNpfuzU")
                                .sig("KEL5U1lLRkknEoGgQQpOuDEqgZT20AggzVhzIuRVxiAeVJPT798vObTXLRdse6oRbHrFMg4rfSSFFLJjUHCRDw")
                                .build()
                ))
                .build();

        Verifier verifier = engine.newVerifier(publicKey);
        assertThat(verifier.verifyJson(signedJson)).isTrue();

        testMessage.hello = "xxxxx";
        assertThat(verifier.verifyJson(signedJson)).isFalse();
    }

    PublicKey samplePublicKey() {
        return engine.unmarshalPublicKey("QkF2rXywcANez0q7Yk-U_Yslfcg7ffOkurkbd7d6Vn0");
    }
}