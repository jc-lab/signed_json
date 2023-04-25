package kr.jclab.javautils.signedjson.keys;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import kr.jclab.javautils.signedjson.StaticHolder;
import kr.jclab.javautils.signedjson.Verifier;
import kr.jclab.javautils.signedjson.model.SignedJson;
import kr.jclab.javautils.signedjson.model.SignedJsonSignature;

import java.nio.charset.StandardCharsets;
import java.util.Optional;

public abstract class AbstractVerifier implements Verifier {
    @Override
    public <T> boolean verifyJson(SignedJson<T> message) {
        return verifyJson(message, null);
    }

    @Override
    public <T> boolean verifyJson(SignedJson<T> message, ObjectMapper objectMapper) {
        if (objectMapper == null) {
            objectMapper = StaticHolder.getObjectMapper();
        }
        try {
            String keyId = this.getKeyId();
            String singingPart = objectMapper.writeValueAsString(message.getSigned());
            Optional<SignedJsonSignature> matchedSignature = message.getSignatures()
                    .stream()
                    .filter(v -> keyId.equals(v.getKeyid()))
                    .findAny();
            if (!matchedSignature.isPresent()) {
                return false;
            }

            return verifyMessage(singingPart.getBytes(StandardCharsets.UTF_8), StaticHolder.getDecoder().decode(matchedSignature.get().getSig()));
        } catch (JsonProcessingException e) {
            throw new RuntimeException(e);
        }
    }
}
