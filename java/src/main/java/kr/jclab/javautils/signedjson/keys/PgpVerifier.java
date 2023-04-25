package kr.jclab.javautils.signedjson.keys;

import kr.jclab.javautils.signedjson.StaticHolder;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPContentVerifierBuilderProvider;

import java.io.*;
import java.security.PublicKey;

public class PgpVerifier extends AbstractVerifier {
    private final PgpEngine engine;
    private final PgpPublicKey publicKey;

    public PgpVerifier(PgpEngine engine, PgpPublicKey pgpPublicKey) {
        this.engine = engine;
        this.publicKey = pgpPublicKey;
    }

    @Override
    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    @Override
    public String getKeyId() {
        return this.engine.getKeyId(this.publicKey);
    }

    @Override
    public boolean verifyMessage(byte[] data, byte[] sig) {
        try {
            PGPSignature signature = verifySignature(new ByteArrayInputStream(sig), this.publicKey.getKeyRing().getPublicKey());
            signature.update(data);
            return signature.verify();
        } catch (IOException | PGPException e) {
            throw new RuntimeException(e);
        }
    }

    static PGPSignature verifySignature(
            InputStream in,
            PGPPublicKey key
    ) throws IOException, PGPException {
        in = PGPUtil.getDecoderStream(in);

        JcaPGPObjectFactory pgpFact = new JcaPGPObjectFactory(in);
        PGPSignatureList p3;

        Object o = pgpFact.nextObject();
        if (o instanceof PGPCompressedData) {
            PGPCompressedData c1 = (PGPCompressedData) o;

            pgpFact = new JcaPGPObjectFactory(c1.getDataStream());

            p3 = (PGPSignatureList) pgpFact.nextObject();
        } else {
            p3 = (PGPSignatureList) o;
        }

        PGPSignature sig = p3.get(0);
        sig.init(new JcaPGPContentVerifierBuilderProvider().setProvider(StaticHolder.getBcProvider()), key);
        return sig;
    }
}
