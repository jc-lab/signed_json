package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.Verifier;
import kr.jclab.javautils.signedjson.model.SignedJson;
import kr.jclab.javautils.signedjson.model.SignedJsonSignature;
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey;
import org.junit.jupiter.api.Test;

import java.security.PublicKey;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.*;

class PgpEngineTest {
    private final PgpEngine engine = new PgpEngine();

    @Test
    void getSchema() {
        assertThat(engine.getSchema()).isEqualTo("pgp");
    }

    @Test
    void marshalPublicKey() {
        PublicKey publicKey = samplePublicKey();
        String encodedPublicKey = engine.marshalPublicKey(publicKey);
        assertThat(encodedPublicKey).isEqualTo("mQGNBGRF9dEBDACyS_w8cGfEggrA-IkI179SH2gSwUFL-lAmDSeOHWq8m_7do5sh7cbaYKEmGsigrLsa0BvdHwMS6N9KGvKWK2MIr7w-PV1-B_e4sr9mSIBbZEjEqaNVrO8inspGwYiIC28EefqlIFgUs5DGaZ-EvYepTLsnNZPuyQYqURhZ_X50wCWWorHEAzd68mRKQXjM9LEyxC3inKf6rLNVAYBUYhuZ7pAzq1ZqwmspzihZCHlFTraC7a4kgVul0EICHTuxgQEWJV_r2cODvvHspwUpBYkuSOt2lDyVIweE06Bg--Efh3opZ7xQNkKqiOlOO5r0xhtJCbllIeFt5SP6C1EM8n72jsc890DxcXhP0jlriPOAfNecWrOVoyg9frlFIiMCMExzRjhf_NKteJkBqMymOr11Hv4j-n-XW5_y9_xuz_ojX91AElNwVzZ6qoHdJ9PVVBt9MTio67S0W48mB6voJEsfqXqiMpD0Xrnx8cQuwP_ooD6Li8mKc3e0lEGzAO8DslMAEQEAAbQfdGVzdC1yc2EgPHRlc3QtcnNhQGV4YW1wbGUuY29tPokB1AQTAQoAPhYhBFRYyZaQPG2zrvo3eoMUtCYA09lmBQJkRfXRAhsDBQkDw7NfBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJEIMUtCYA09lmKAAL_Ao9EhtWdwxOfnNhOiGO92yGl_jy-S-RX-x56AQrX3BX0p12GTp4WmRC8rSG_QLICNx7Sg8RGxw0YGgv7loD7zVht_3crDmiSstGM4qnadSvWDVRm3ykbkxdXN9qlukDr--RZyb_5SV9V97INBHrRW8rUuVX91Ggc8WlkHBIF7StvXGOpCsi9zZOh-Iqjle_-fMPRH5DEZQL8yTdEcVWP8bZTb24dERxoIxg9BkSMJKcgOQjXD3SA1wMHY-f1e6sP_V-w8NgSvMICqoQA5PXpO7n4Jb1a18L6SwqIYaq2RgJdei61QDW4zAqnVMsQ43_exVBpFrfMpG-bDqVuZBjanomSe1Fhj5rOXSO8CYlPs9FOtwyrhfeEYhDlQVvNxKmbO4KgZ1_XIAVKKWSWnAdicqzNZzmOAZ0ADrRt3vU4HVv_1jDbOXt2t9kfqpMCVCOIlErWhrv46JZ3o2pE8KADuuj_ULE5806xO1GTqbk41NeAsIt-0xNIUKLC2U3oe4qELkBjQRkRfXRAQwAv4B7SCwHDaYcaN90_mr21HOSue69BfsxJGTkn287rbOI2b3rqerS1HlBtn-88ip4mk4wBhcLa_L5-Jm6bOIs6HWSl2qlTjCf2FIi1vzyslvNrP1NhxIzh1zuIU_Uwif7F_4ZAb3gwGlDScjV9xGRKL-CJ6K73lNvtAqT1Cwia0JLOa5tRsB1vccJMyhmCEkHgEQuEGYIQ6vjYDYhP1in7FrJp5QVKD6pDxltfaXCFD6DimR6gbcXIcBF2AP1myvGi2SyPYJfeIltXqTqjR73opqetbcw2JvKT9Ya8gJSB6WkRqSixiBFXRPmXLt_al6FytDCXC4Zuc2BzwOky6LpaXY__4MFewnmiMs_sg-pNsBowHzIY05F3O5DrJMctQefIMVkJl6ug2odyI1OKX2VKYdKEFuUNNwF2K7dlz7kq_iYvuqFZQhf6evVrV29IJwDaoNAzk-Xu3jVEFTXSp3LDihHdO-llAtrSHtEiSeCfRUEhMvIvQ6AYnFcs449W7AZABEBAAGJAbwEGAEKACYWIQRUWMmWkDxts676N3qDFLQmANPZZgUCZEX10QIbDAUJA8OzXwAKCRCDFLQmANPZZtz5C_9kK5pCXrEo3UQZG8dX1Ccjd1MJOpbWjsmErVNGLbpCsZXRmKA42bcjoqHt97FccPYqfhQmSGZIqAqCCDkW8gFYJsAMi-E_SRjp2K_-_BEHMIGXgcNsEEpAIRooRBXBhQ8_VOAAfVqp7TTir4OYWK5-J-4JhfCnWssC4AqzLFsWqHS0LylzoWc-mtuDdykY2knBykDcrEKDMroZquDWtyTYwHNlulj4B6PBFwIgNTpqkkSKnjsPnsjoi6pyw9rDHZGfAgvXvzB4X0YDfPR7TqJTKGFikBtan7G7HpmiHqUo8Ara1EgaBvh9X9-8-y46QFoa0LU63DcW6rx2Olj_iVhqIu6zoQcCzlT3zrzCQ5mFcZYwIkFaInVIMPbuj54gujOb9wTZcY_yqniPVAaN0tjZRg8ltAhtLMZNjJ91DLe1BZQ5s8YlaEM1tGguhvNciPEyPJW1Zotocy_i-8JSCD8lrzZxsgoqu5t2VVxYfsf6LULHjZBok6oROZ4FKgfCz1k");

        PublicKey rekey = engine.unmarshalPublicKey(encodedPublicKey);
        assertThat(rekey).isNotNull().isOfAnyClassIn(PgpPublicKey.class, PublicKey.class);
    }

    @Test
    void unmarshalPublicKey() {
        PublicKey publicKey = samplePublicKey();
        assertThat(publicKey).isNotNull().isOfAnyClassIn(PgpPublicKey.class, PublicKey.class);
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
        assertThat(keyId).isEqualTo("VFjJlpA8bbOu-jd6gxS0JgDT2WY");
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
                                .keyid("VFjJlpA8bbOu-jd6gxS0JgDT2WY")
                                .sig("wsDzBAABCAAnBQJkR2cZCZCDFLQmANPZZhYhBFRYyZaQPG2zrvo3eoMUtCYA09lmAAD7bAv8DFQZiGV9qpf16ZOLDc1EUmOW0oc4_RgLGL3N0KfQ6aXY9LWMdSVzkzkuEXRagP8m9hj5lDL_58yONwumFz0YaHTT-bA9G7Exjmnq4esnRHTu-6s8JAHKgoAsoybYZE7Yl-6TvsOARSIAXqUm83IGrJpChxFsHl0cIfgpuldnIxK6OkCHU-TuOmsKef7AR41oZf8qLhG6Xmr8m5Sg2ztymr-FCsrVDs-MV-0qcQNU_9-p7f9l-y9NIqRaCe9bool-Xxn-DQ5iLcUM_mo-a7XSiAHbxBLtnGYLmT8aq6A8yHWuuk2eLm5d1y4WoJplw9mzdvvR7PxPd0xZvpaQqLtTU8l6RBIq4NVX5OUPkQrcvRlTIg47mBKWhc1V0uZ8VRx_jT84KQ0zBOL5e8WcIeHC6cBNKX93fQxOPCsN9cosfP6Ke0A7VVonSZpJiFhjOzChT-m5AYk52EvARVrh2cEnOfQ0HXNoLjHOJNSrctuGLbXMyjROQsonQgzSXKHe3DQu")
                                .build()
                ))
                .build();

        Verifier verifier = engine.newVerifier(publicKey);
        assertThat(verifier.verifyJson(signedJson)).isTrue();

        testMessage.hello = "xxxxx";
        assertThat(verifier.verifyJson(signedJson)).isFalse();
    }

    PublicKey samplePublicKey() {
        return engine.unmarshalPublicKey("-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: User-ID:\ttest-rsa <test-rsa@example.com>\nComment: Created:\t23. 4. 24. 오후 12:21\nComment: Expires:\t25. 4. 24. 오후 12:00\nComment: Type:\t3,072-bit RSA (secret key available)\nComment: Usage:\tSigning, Encryption, Certifying User-IDs\nComment: Fingerprint:\t5458C996903C6DB3AEFA377A8314B42600D3D966\n\n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\nVVxYfsf6LULHjZBok6oROZ4FKgfCz1k=\n=lSR3\n-----END PGP PUBLIC KEY BLOCK-----\n");
    }
}