package com.github.glusk2.wse.common.net;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;

public final class SocketChannelIncomingPacket implements IncomingPacket {

    private final SocketChannel sc;
    private final ByteBuffer buf;

    public SocketChannelIncomingPacket(SocketChannel sc, int size) {
        this(sc, ByteBuffer.allocate(size));
    }

    public SocketChannelIncomingPacket(SocketChannel sc, ByteBuffer buf) {
        this.sc = sc;
        this.buf = buf.duplicate();
    }

    /** Not thread-safe! */
    @Override
    public ByteBuffer buffer() throws IOException {
        sc.read(buf);
        return buf.duplicate();
    }
}
