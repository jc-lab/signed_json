package kr.jclab.javautils.signedjson.util;

import kr.jclab.javautils.signedjson.StaticHolder;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class HashUtil {
    public static String sha256Encode(byte[] input) {
        try {
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256", StaticHolder.getBcProvider());
            messageDigest.update(input);
            return StaticHolder.getEncoder().encodeToString(messageDigest.digest());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }
}
