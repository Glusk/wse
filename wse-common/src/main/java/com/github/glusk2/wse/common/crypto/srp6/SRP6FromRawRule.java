package com.github.glusk2.wse.common.crypto.srp6;

import java.nio.ByteOrder;

import com.github.glusk2.wse.common.util.Mapping;

public class SRP6FromRawRule implements Mapping<byte[], SRP6Integer> {

    private final int size;
    private final ByteOrder order;
    
    public SRP6FromRawRule(int size, ByteOrder order) {
        this.size = size;
        this.order = order;
    }
    
    @Override
    public SRP6Integer map(byte[] key) {
        return new SRP6PrecomputedValue(key, size, order);
    }
}
