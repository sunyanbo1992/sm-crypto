package com.sm.sm2;

import org.testng.annotations.Test;

import java.math.BigInteger;

import static org.testng.Assert.*;

/**
 * @author Shengzhao Li
 */
public class SM2SignResultTest {


    /**
     * 测试生成与 解析
     *
     * @throws Exception
     */
    @Test
    public void parse() throws Exception {

        BigInteger s = new BigInteger(1, "2332233".getBytes());
        BigInteger r = new BigInteger(1, "555852221455555".getBytes());
        SM2SignResult result = new SM2SignResult(r, s);

        final String base64 = result.resultToBase64();
        assertNotNull(base64);
//        System.out.println(base64);


        final SM2SignResult parseResult = SM2SignResult.parse(base64);
        assertNotNull(parseResult);
        assertEquals(parseResult.resultToBase64(), base64);

    }


}