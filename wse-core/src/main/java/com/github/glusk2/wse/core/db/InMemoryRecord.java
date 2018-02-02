package com.github.glusk2.wse.core.db;

import java.math.BigInteger;
import java.nio.ByteOrder;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.sql.SQLException;
import java.util.Locale;

import com.github.glusk2.wse.common.crypto.srp6.SRP6FromBigIntRule;
import com.github.glusk2.wse.common.crypto.srp6.SRP6FromRawRule;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;
import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6PrivateKey;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Record;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Verifier;
import com.github.glusk2.wse.common.crypto.util.hashing.ImdSimpleCopy;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;

public final class InMemoryRecord implements SRP6Record {

    private static final int HEX_RADIX = 16;
    private static final int SHA1_LENGTH = 20;
    private static final int DEFAULT_INT_LENGTH = 32;

    private final SRP6Integer v;
    private final SRP6Integer s;
    private final SRP6Integer N;
    private final SRP6Integer g;

    public InMemoryRecord(
        SRP6Integer N,
        SRP6Integer g,
        SRP6Integer s,
        String I,
        String P,
        ImmutableMessageDigest imd
    ) {
        this(
            s,
            new SRP6Verifier(
                N,
                g,
                new SRP6PrivateKey(
                    imd,
                    s,
                    P,
                    I,
                    new SRP6FromRawRule(
                        SHA1_LENGTH,
                        ByteOrder.LITTLE_ENDIAN
                    )
                ),
                new SRP6FromBigIntRule(
                    N.bytes().length,
                    ByteOrder.LITTLE_ENDIAN
                )
            ),
            N,
            g
        );
    }

    public InMemoryRecord(
        SRP6Integer s,
        SRP6Integer v,
        SRP6Integer N,
        SRP6Integer g
    ) {
        this.s = s;
        this.v = v;
        this.N = N;
        this.g = g;
    }

    @Override
    public SRP6Integer verifier() throws SQLException {
        return this.v;
    }

    @Override
    public SRP6Integer salt() throws SQLException {
        return this.s;
    }

    @Override
    public SRP6Integer modulus() throws SQLException {
        return this.N;
    }

    @Override
    public SRP6Integer generator() throws SQLException {
        return this.g;
    }

    public static void main(final String[] args) throws Exception {
        String username = args[0].toUpperCase(Locale.US);
        String password = args[1].toUpperCase(Locale.US);
        SRP6Record acc =
            new InMemoryRecord(
                new SRP6PrecomputedValue(
                    new BigInteger(
                        ("894B645E 89E1535B BDAD5B8B 29065053" +
                         "0801B18E BFBF5E8F AB3C8287 2A3E9BB7"
                        ).replaceAll(" ", ""),
                        HEX_RADIX
                    )
                ),
                new SRP6PrecomputedValue(
                    new BigInteger("7")
                ),
                new SRP6PrecomputedValue(
                    new BigInteger(
                        1,
                        new SecureRandom().generateSeed(DEFAULT_INT_LENGTH)
                    )
                ),
                username,
                password,
                new ImdSimpleCopy(MessageDigest.getInstance("SHA-1"))
            );
        System.out.format(
            "Record:%n--------%nI: %s%nN: %s%ng: %s%nv: %s%ns: %s%n",
            username,
            acc.modulus().bigInteger().toString(HEX_RADIX),
            acc.generator().bigInteger().toString(HEX_RADIX),
            acc.verifier().bigInteger().toString(HEX_RADIX),
            acc.salt().bigInteger().toString(HEX_RADIX)
        );
    }
}
