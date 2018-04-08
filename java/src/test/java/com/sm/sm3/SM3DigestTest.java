/*
 * Copyright (c) 2016 BeiJing JZYT Technology Co. Ltd
 * www.idsmanager.com
 * All rights reserved.
 *
 * This software is the confidential and proprietary information of
 * BeiJing JZYT Technology Co. Ltd ("Confidential Information").
 * You shall not disclose such Confidential Information and shall use
 * it only in accordance with the terms of the license agreement you
 * entered into with BeiJing JZYT Technology Co. Ltd.
 */
package com.sm.sm3;

import org.testng.annotations.Test;

import java.io.IOException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertNotNull;

/**
 * @author William Sun
 */
public class SM3DigestTest {

    @Test
    public void sm3HexTest() throws IOException {

        String msg1 = "abc";
        String msg2 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";//512bit消息；

        String actual1 = SM3Digest.getHexHash(msg1);
        String actual2 = SM3Digest.getHexHash(msg2);

        String expect1 = "66C7F0F462EEEDD9D1F2D46BDC10E4E24167C4875CF2F7A2297DA02B8F4BA8E0";
        String expect2 = "DEBE9FF92275B8A138604889C18E5A4D6FDB70E5387E5765293DCBA39C0C5732";

        assertEquals(actual1,expect1);
        assertEquals(actual2,expect2);
    }

    @Test
    public void sm3Base64Test() throws IOException {

        String msg1 = "abc";
        String msg2 = "abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";//512bit消息；

        String actual1 = SM3Digest.getBase64Hash(msg1);
        String actual2 = SM3Digest.getBase64Hash(msg2);

        assertNotNull(actual1);
        assertNotNull(actual2);
    }
}


