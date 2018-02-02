package com.github.glusk2.wse.common.net;

import java.io.IOException;

public interface OutgoingPacket {
    /** @return  {@code true} if therse's still unsent packet data. */
    boolean send() throws IOException;
    default void sendFull() throws IOException {
        boolean hasMoreToSend = true;
        do {
            hasMoreToSend = send();
        } while (hasMoreToSend);
    }
}
