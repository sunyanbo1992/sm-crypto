package com.sm.sm2;

import org.testng.annotations.Test;

import static org.testng.Assert.assertTrue;

public class SM2VerifyTest {

    @Test
    public void verifyTest() throws Exception {

        String userId = "ALICE123@YAHOO.COM";
        String plainText = "message digest";
        String publicKey = "BMx6kqJ0+YL4O91LRgnXQ7DA1EWay3nGvD92pFajAmftTmUKUjkn72RppgAOMZTsI/QliOudQ7YQ70ZaEhgLAZc=";
        String base64  = "OTIyMjE5MDk3MjUxNDAyMDc1NTU2OTczODc2NTQ0ODAyMzQ0MzA2MDgyMzEwNzU2NzY0MTg1MTcwMDA5NDY5ODAxMDU1MDU0ODQwMzI6MTA1Mzc1NzY2Njk2NTg4NTczMzY2NjM4NTgzMTc0NzI2MTE5NDQzODc2Njg5MjcwMzkxMTU1NjEzMzI5NTg1MzQwNTIxNTk2NTk1MzE4";
        SM2VerifyParams sm2VerifyParams = new SM2VerifyParams(userId.getBytes(), publicKey, plainText.getBytes(), base64);
        assertTrue(SM2Verify.verify(sm2VerifyParams, true));
    }
}