package kr.jclab.javautils.signedjson.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.ToString;
import lombok.extern.jackson.Jacksonized;

import java.util.ArrayList;
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
    @lombok.Builder.Default
    private final List<SignedJsonSignature> signatures = new ArrayList<>();
}
