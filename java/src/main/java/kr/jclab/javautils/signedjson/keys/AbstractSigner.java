package kr.jclab.javautils.signedjson.keys;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.jclab.javautils.signedjson.Signer;
import kr.jclab.javautils.signedjson.StaticHolder;
import kr.jclab.javautils.signedjson.model.SignedJson;
import kr.jclab.javautils.signedjson.model.SignedJsonSignature;

import java.nio.charset.StandardCharsets;

public abstract class AbstractSigner implements Signer {
    @Override
    public <T> void signJson(SignedJson<T> message) {
        signJson(message, null);
    }

    @Override
    public <T> void signJson(SignedJson<T> message, ObjectMapper objectMapper) {
        if (objectMapper == null) {
            objectMapper = StaticHolder.getObjectMapper();
        }
        try {
            String keyId = this.getKeyId();
            String singingPart = objectMapper.writeValueAsString(message.getSigned());

            byte[] sig = signMessage(singingPart.getBytes(StandardCharsets.UTF_8));
            message.getSignatures().add(SignedJsonSignature.builder()
                    .keyid(keyId)
                    .sig(StaticHolder.getEncoder().encodeToString(sig))
                    .build());
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
