package com.github.glusk2.wse.common.net;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public final class SocketChannelOutgoingPacket implements OutgoingPacket {

    private final SocketChannel sc;
    private final ByteBuffer buf;

    public SocketChannelOutgoingPacket(SocketChannel sc, ByteBuffer buf) {
        this.sc = sc;
        this.buf = buf.duplicate();
    }

    /** Not thread-safe! */
    @Override
    public boolean send() throws IOException {
        sc.write(buf);
        return buf.hasRemaining();
    }
}
