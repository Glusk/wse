package com.github.glusk2.wse.core.db;

import static org.junit.Assert.fail;

import java.security.MessageDigest;
import java.util.stream.Stream;

import org.junit.Test;

import com.github.glusk2.wse.common.crypto.srp6.SRP6Record;
import com.github.glusk2.wse.common.crypto.util.hashing.DigestArgument;
import com.github.glusk2.wse.common.crypto.util.hashing.ImdSimpleCopy;
import com.github.glusk2.wse.common.crypto.util.hashing.ImmutableMessageDigest;
import com.github.glusk2.wse.common.crypto.util.hashing.StringArgument;
import com.github.glusk2.wse.common.util.Comparison;

public class FakeRecordTest {
    @Test
    public void test() {
        try {
            ImmutableMessageDigest imd =
                new ImdSimpleCopy(MessageDigest.getInstance("SHA-1"));
            DigestArgument seedKey = new StringArgument("Top secret");
            String username = "Alice";
            int N = 100;
            SRP6Record[] records = 
                Stream.generate(() -> new FakeRecord(imd, seedKey, username))
                      .limit(N)
                      .toArray(SRP6Record[]:: new);
            for (int i = 1; i < N; i++) {
                if (new Comparison<>(records[i-1], records[i]).value() != 0) {
                    fail("Records don't match!");
                }
            }
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }
}
