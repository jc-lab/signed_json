# signed-json

### SignedJsonRoot

```
{
  "signed": SIGNED_MESSAGE,
  "signature": {
    "keyid": KEYID,
    "sig": SIGNATURE
  }
}
```

#### SIGNED_MESSAGE

Signed json object.

#### KEYID

The identifier of the key, which is a base64-url-encoded of the SHA-256 hash of the canonical form of the key.

#### SIGNATURE

A base64-url-encoded signature of the canonical form of the metadata.

# Sample

```json
{
  "signed": {
    "hello": "WORLD"
  },
  "signatures": [
    {
      "keyid": "EUC_wk4IQSWkp2QFLzUWXQIFt_3R3oMa2O8fzNpfuzU",
      "sig": "KEL5U1lLRkknEoGgQQpOuDEqgZT20AggzVhzIuRVxiAeVJPT798vObTXLRdse6oRbHrFMg4rfSSFFLJjUHCRDw"
    }
  ]
}
```

# License

[Apache-2.0](./LICENSE)

