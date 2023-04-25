package kr.jclab.javautils.signedjson;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.setl.json.jackson.CanonicalFactory;
import kr.jclab.javautils.signedjson.keys.Ed25519Engine;
import kr.jclab.javautils.signedjson.keys.PgpEngine;
import kr.jclab.javautils.signedjson.util.KotlinHelper;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class StaticHolder {
    public static class LazyHolder {
        public static BouncyCastleProvider BC_PROVIDER = new BouncyCastleProvider();
        public static Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
        public static Base64.Decoder DECODER = Base64.getUrlDecoder();
        public static LazyHolder INSTANCE = new LazyHolder();

        private final ObjectMapper objectMapper;

        private final Map<String, KeyEngine> engines;

        public KeyEngine getEngine(String schema) {
            return engines.get(schema);
        }

        public LazyHolder() {
            this.objectMapper = new ObjectMapper(new CanonicalFactory());

            if (isSupportKotlin(this.getClass().getClassLoader())) {
                this.objectMapper.registerModule(KotlinHelper.createJacksonKotlinModule());
            }
            this.engines = new HashMap<String, KeyEngine>() {{
                put("ed25519", new Ed25519Engine());
                put("pgp", new PgpEngine());
            }};
        }
    }

    public static BouncyCastleProvider getBcProvider() {
        return LazyHolder.BC_PROVIDER;
    }

    public static Base64.Encoder getEncoder() {
        return LazyHolder.ENCODER;
    }

    public static Base64.Decoder getDecoder() {
        return LazyHolder.DECODER;
    }

    public static KeyEngine getEngine(String schema) {
        return LazyHolder.INSTANCE.getEngine(schema);
    }

    public static ObjectMapper getObjectMapper() {
        return LazyHolder.INSTANCE.objectMapper;
    }

    public static boolean isSupportKotlin(ClassLoader classLoader) {
        try {
            classLoader.loadClass("com.fasterxml.jackson.module.kotlin.KotlinModule");
            return true;
        } catch (Exception e) {}
        return false;
    }
}
