package com.github.glusk2.wse.core.logon.auth;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.sql.SQLException;

import com.github.glusk2.wse.common.crypto.srp6.SRP6FromBigIntRule;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Integer;
import com.github.glusk2.wse.common.crypto.srp6.SRP6PrecomputedValue;
import com.github.glusk2.wse.common.crypto.srp6.SRP6Record;
import com.github.glusk2.wse.common.crypto.srp6.SRP6SrvPubEphVal;
import com.github.glusk2.wse.common.net.IncomingPacket;
import com.github.glusk2.wse.common.util.Mapping;

/**
 * A reference Authentication Logon Challenge implementation.
 */
public final class ReferenceALC implements AuthLogonChallenge {

    private static final byte OPCODE = 0;
    private static final byte LOGIN_OK = 0;
    private static final int IDENTITY_OFFSET =
        4 +      // game name
        3 * 1 +  // 3 version bytes
        2 +      // build number
        5 * 4;   // platform, architecture, locale, timezone bias, ip
    private static final int DEFAULT_RNG_BYTE_COUNT = 32;
    private static final int INT_PAD_LENGTH = 32;
    private static final int SEED_LENGTH = 16;

    private final IncomingPacket cc;
    private final Mapping<String, SRP6Record> records;
    private final SRP6Integer b;

    public ReferenceALC(
        IncomingPacket cc,
        Mapping<String, SRP6Record> records
    ) {
        this(
            cc,
            new SRP6PrecomputedValue(
                new BigInteger(
                    1,
                    new SecureRandom().generateSeed(DEFAULT_RNG_BYTE_COUNT)
                )
            ),
            records
        );
    }

    public ReferenceALC(
        IncomingPacket cc,
        SRP6Integer b,
        Mapping<String, SRP6Record> records
    ) {
        this.cc = cc;
        this.b = b;
        this.records = records;
    }

    /** {@inheritDoc} */
    @Override
    public String identity() throws IOException {
        ByteBuffer buf = (ByteBuffer) cc
            .buffer()
            .order(ByteOrder.LITTLE_ENDIAN)
            .position(IDENTITY_OFFSET);
        byte[] I = new byte[Byte.toUnsignedInt(buf.get())];
        buf.get(I);
        return new String(I, StandardCharsets.UTF_8);
    }

    @Override
    public SRP6Record record() throws IOException {
        return records.map(identity());
    }

    @Override
    public SRP6Integer srvPrvEphVal() {
        return b;
    }

    @Override
    public SRP6Integer srvPubEphVal() throws SQLException, IOException {
        return
            new SRP6SrvPubEphVal(
                record().modulus(),
                record().generator(),
                record().verifier(),
                srvPrvEphVal(),
                new SRP6FromBigIntRule(INT_PAD_LENGTH, ByteOrder.LITTLE_ENDIAN)
            );
    }

    @Override
    public ByteBuffer response() throws SQLException, IOException {
        byte[] B = srvPubEphVal().bytes();
        byte[] g = record().generator().bytes();
        byte[] N = record().modulus().bytes();
        byte[] s = record().salt().bytes();
        ByteBuffer packet =
            ByteBuffer.allocate(
                1 + 1 + 1 + B.length + 1 + g.length + 1 + N.length +
                INT_PAD_LENGTH + SEED_LENGTH + 1
            ).order(ByteOrder.LITTLE_ENDIAN);
        packet.put(OPCODE);
        packet.put((byte) 0); // unknown, must be 0
        packet.put(LOGIN_OK);
        packet.put(B);
        packet.put((byte) g.length);
        packet.put(g);
        packet.put((byte) N.length);
        packet.put(N);
        packet.put(s);
        packet.position(packet.position() + SEED_LENGTH); // skip ver chk seed
        packet.put((byte) 0); // extra security type (0=no extra security)
        return (ByteBuffer) packet.flip();
    }
}
