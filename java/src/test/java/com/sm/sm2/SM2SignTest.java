package com.sm.sm2;

import org.testng.annotations.Test;

import static org.testng.Assert.assertEquals;

public class SM2SignTest {

    @Test
    public void sm2SignTest() throws Exception {

        String userId = "ALICE123@YAHOO.COM";
        String plainText = "message digest";
        String privateKey = "AOlX6E5hqij+X1h7naAdhzRR/mjDD2sTx2tdXdAF/yEL";
        String expect = "OTIyMjE5MDk3MjUxNDAyMDc1NTU2OTczODc2NTQ0ODAyMzQ0MzA2MDgyMzEwNzU2NzY0MTg1MTcwMDA5NDY5ODAxMDU1MDU0ODQwMzI6MTA1Mzc1NzY2Njk2NTg4NTczMzY2NjM4NTgzMTc0NzI2MTE5NDQzODc2Njg5MjcwMzkxMTU1NjEzMzI5NTg1MzQwNTIxNTk2NTk1MzE4";
        SM2SignResult sm2SignTest = SM2Sign.signUseBase64(userId, privateKey, plainText, true);
        assertEquals(sm2SignTest.resultToBase64(),expect);

    }
}