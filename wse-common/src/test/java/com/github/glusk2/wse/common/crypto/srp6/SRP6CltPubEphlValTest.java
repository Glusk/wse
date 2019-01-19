package com.github.glusk2.wse.common.crypto.srp6;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.ByteOrder;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorUcA;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorUcN;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorLcA;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorLcG;
import com.github.glusk2.wse.common.util.Mapping;

public class SRP6CltPubEphlValTest {
    @Test
    public void testRFC5054() {
        final Mapping<BigInteger, SRP6Integer> rule = 
            new SRP6FromBigIntRule(
                new TestVectorUcN().bytes().length,
                ByteOrder.BIG_ENDIAN
            );
        
        assertTrue(
            "Computed value doesn't match the test vector.",
            new TestVectorUcA().string().equals(
                new SRP6CltPubEphVal(
                    new TestVectorUcN(),
                    new TestVectorLcG(),
                    new TestVectorLcA(),
                    rule
                ).string()
            )
        );
    }
}
