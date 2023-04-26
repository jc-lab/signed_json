package kr.jclab.javautils.signedjson;

import com.fasterxml.jackson.databind.ObjectMapper;
import kr.jclab.javautils.signedjson.model.SignedJson;

import java.security.PrivateKey;
import java.security.PublicKey;

public interface Signer {
    PrivateKey getPrivateKey();
    PublicKey getPublicKey();
    String getKeyId();
    byte[] signMessage(byte[] data);
    <T> void signJson(SignedJson<T> message);
    <T> void signJson(SignedJson<T> message, ObjectMapper objectMapper);
}
