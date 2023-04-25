package kr.jclab.javautils.signedjson;

import com.fasterxml.jackson.databind.ObjectMapper;
import kr.jclab.javautils.signedjson.model.SignedJson;

import java.security.PublicKey;

public interface Verifier {
    PublicKey getPublicKey();
    String getKeyId();
    boolean verifyMessage(byte[] data, byte[] sig);
    <T> boolean verifyJson(SignedJson<T> message);
    <T> boolean verifyJson(SignedJson<T> message, ObjectMapper objectMapper);
}
