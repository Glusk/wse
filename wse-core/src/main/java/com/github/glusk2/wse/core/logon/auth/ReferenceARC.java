package com.github.glusk2.wse.core.logon.auth;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.net.IncomingPacket;

/**
 * A reference Authentication Reconnect Challenge implementation.
 */
public final class ReferenceARC implements AuthReconnectChallenge {

    private static final byte OPCODE = 2;
    private static final int SALT_LENGTH = 16;
    private static final int UNKNOWN_LENGTH = 16;
    private static final int IDENTITY_OFFSET =
            4 +      // game name
            3 * 1 +  // 3 version bytes
            2 +      // build number
            5 * 4;   // platform, architecture, locale, timezone bias, ip

    private final IncomingPacket clientChallenge;
    private final DigestArgument salt;

    public ReferenceARC(IncomingPacket clientChallenge) {
        this(
            clientChallenge,
            new DigestArgument.RAW_BYTES(
                new SecureRandom().generateSeed(SALT_LENGTH)
            )
        );
    }

    public ReferenceARC(
        IncomingPacket clientChallenge,
        DigestArgument salt
    ) {
        this.clientChallenge = clientChallenge;
        this.salt = salt;
    }

    /** {@inheritDoc} */
    @Override
    public String identity() throws IOException {
        ByteBuffer buf = (ByteBuffer) clientChallenge
            .buffer()
            .order(ByteOrder.LITTLE_ENDIAN)
            .position(IDENTITY_OFFSET);
        byte[] I = new byte[Byte.toUnsignedInt(buf.get())];
        buf.get(I);
        return new String(I, StandardCharsets.UTF_8);
    }

    @Override
    public DigestArgument serverSalt() {
        return salt;
    }

    @Override
    public ByteBuffer response() throws Exception {
        ByteBuffer packet =
            ByteBuffer
                .allocate(1 + 1 + SALT_LENGTH + UNKNOWN_LENGTH)
                .order(ByteOrder.LITTLE_ENDIAN);
        packet.put(OPCODE);
        packet.position(packet.position() + 1); //error=0
        packet.put(serverSalt().bytes());
        packet.position(packet.position() + UNKNOWN_LENGTH);
        return (ByteBuffer) packet.flip();
    }
}
