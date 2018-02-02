package com.github.glusk2.wse.common.net;

import java.nio.ByteBuffer;

public interface Response {
    ByteBuffer response() throws Exception;
}
