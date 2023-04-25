package kr.jclab.javautils.signedjson.util;

import com.fasterxml.jackson.databind.Module;
import com.fasterxml.jackson.module.kotlin.KotlinModule;

public class KotlinHelper {
    public static Module createJacksonKotlinModule() {
        return new KotlinModule.Builder().build();
    }
}
