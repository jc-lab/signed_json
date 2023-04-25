package kr.jclab.javautils.signedjson.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.jackson.Jacksonized;

@Getter
@Jacksonized
@ToString
@EqualsAndHashCode
@lombok.Builder(builderClassName = "Builder")
public class SignedJsonSignature {
    @JsonProperty("keyid")
    private final String keyid;
    @JsonProperty("sig")
    private final String sig;
}
