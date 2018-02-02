package com.github.glusk2.wse.core.logon.auth;

import java.io.IOException;
import java.nio.ByteOrder;

import com.github.glusk2.wse.common.net.IncomingPacket;

/**
 * A reference Client Authentication Challenge Header implementation.
 */
public final class ReferenceCACH implements ClientAuthChallengeHeader {
    private final IncomingPacket header;

    public ReferenceCACH(IncomingPacket header) {
        this.header = header;
    }

    /** {@inheritDoc} */
    @Override
    public byte opcode() throws IOException {
        return this.header.buffer().order(ByteOrder.LITTLE_ENDIAN).get(0);
    }

    /** {@inheritDoc} */
    @Override
    public byte version() throws IOException {
        return this.header.buffer().order(ByteOrder.LITTLE_ENDIAN).get(1);
    }

    /** {@inheritDoc} */
    @Override
    public int size() throws IOException {
        return Short.toUnsignedInt(
            this.header.buffer().order(ByteOrder.LITTLE_ENDIAN).getShort(2)
        );
    }
}
