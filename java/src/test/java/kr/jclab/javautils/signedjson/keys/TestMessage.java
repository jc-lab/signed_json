package kr.jclab.javautils.signedjson.keys;

import com.fasterxml.jackson.annotation.JsonProperty;

public class TestMessage {
    @JsonProperty("hello")
    public String hello;
}
