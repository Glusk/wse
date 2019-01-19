package com.github.glusk2.wse.common.crypto.srp6;

import static org.junit.Assert.assertTrue;

import java.math.BigInteger;
import java.nio.ByteOrder;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorUcA;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorUcN;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorUcS;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorLcB;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorLcU;
import com.github.glusk2.wse.common.crypto.srp6.rfc5054.TestVectorLcV;
import com.github.glusk2.wse.common.util.Mapping;

public class SRP6ServerSecretTest {
    @Test
    public void testRFC5054() {
        final Mapping<BigInteger, SRP6Integer> rule = 
            new SRP6FromBigIntRule(
                new TestVectorUcN().bytes().length,
                ByteOrder.BIG_ENDIAN
            );

        assertTrue(
            "Computed value doesn't match the test vector.",
            new TestVectorUcS().string().equals(
                new SRP6ServerSecret(
                    new TestVectorUcN(),
                    new TestVectorUcA(),
                    new TestVectorLcV(),
                    new TestVectorLcU(),
                    new TestVectorLcB(),
                    rule
                ).string()
            )
        );
    }
}
