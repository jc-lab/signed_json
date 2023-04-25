package kr.jclab.javautils.signedjson.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.jackson.Jacksonized;

import java.util.List;

@Getter
@Jacksonized
@ToString
@EqualsAndHashCode
@lombok.Builder(builderClassName = "Builder")
public class SignedJson<T> {
    @JsonProperty("signed")
    private final T signed;
    @JsonProperty("signatures")
    private final List<SignedJsonSignature> signatures;
}
