package com.github.glusk2.wse.common.net;

import java.io.IOException;
import java.nio.ByteBuffer;

public interface IncomingPacket {
    ByteBuffer buffer() throws IOException;
}
