package com.github.glusk2.wse.core.db;

import java.math.BigInteger;
import java.sql.SQLException;

import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;
import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Record;
import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.Hmac;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.StringArgument;

public final class FakeRecord implements SRP6Record {
    public static final SRP6Integer DEFAULT_MODULUS =
        new SRP6PrecomputedValue(
            new BigInteger(
                ("894B645E 89E1535B BDAD5B8B 29065053" +
                 "0801B18E BFBF5E8F AB3C8287 2A3E9BB7"
                ).replaceAll(" ", ""),
                16
            )
        );
    public static final SRP6Integer DEFAULT_GENERATOR =
        new SRP6PrecomputedValue(new BigInteger("7"));

    private final SRP6Integer verifier;
    private final SRP6Integer salt;
    private final SRP6Integer generator;
    private final SRP6Integer modulus;

    public FakeRecord(
        ImmutableMessageDigest imd,
        DigestArgument seedKey,
        String username
    ) {
        this(imd, seedKey, username, DEFAULT_MODULUS, DEFAULT_GENERATOR);
    }

    public FakeRecord(
        ImmutableMessageDigest imd,
        DigestArgument seedKey,
        String username,
        SRP6Integer modulus,
        SRP6Integer generator
    ) {
        this(
            new SRP6PrecomputedValue(
                new BigInteger(
                    1,
                    new Hmac(
                        imd,
                        seedKey,
                        new StringArgument("verifier".concat(username))
                    ).bytes()
                ),
                modulus.bytes().length
            ),
            new SRP6PrecomputedValue(
                new BigInteger(
                    1,
                    new Hmac(
                        imd,
                        seedKey,
                        new StringArgument("salt".concat(username))
                    ).bytes()
                ),
                modulus.bytes().length
            ),
            modulus,
            generator
        );
    }

    public FakeRecord(
        SRP6Integer verifier,
        SRP6Integer salt,
        SRP6Integer modulus,
        SRP6Integer generator
    ) {
        this.verifier = verifier;
        this.salt = salt;
        this.modulus = modulus;
        this.generator = generator;
    }

    @Override
    public SRP6Integer verifier() throws SQLException {
        return verifier;
    }

    @Override
    public SRP6Integer salt() throws SQLException {
        return salt;
    }

    @Override
    public SRP6Integer modulus() throws SQLException {
        return modulus;
    }

    @Override
    public SRP6Integer generator() throws SQLException {
        return generator;
    }
}
