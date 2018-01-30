package com.github.glusk2.wse.common.util;

public interface Mapping<K, V> {
    V map(K key);
}
