package com.sm.sm2;

import org.testng.annotations.Test;

import java.io.IOException;

import static org.testng.Assert.assertEquals;
import static org.testng.Assert.assertTrue;

/**
 * @author William Sun
 */
public class SM2DecryptTest {

    @Test
    public void decryptHexTest() throws IOException {

        
        String expect = "encryption standard";
        String privateKey = "1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0";
        String cipherText = "04245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144ABF17F6252E776CB9264C2A7E88E52B19903FDC47378F605E36811F5C07423A24B84400F01B8650053A89B41C418B0C3AAD00D886C002864679C3D7360C30156FAB7C80A0276712DA9D8094A634B766D3A285E07480653426D";
        SM2DecryptResult sm2DecryptResult = SM2Decrypt.decryptUseHex(privateKey, cipherText);
        String plainText = new String(sm2DecryptResult.getPlainText());
        boolean c3Result = sm2DecryptResult.getC3Result();
        assertEquals(plainText, expect);
        assertTrue(c3Result);

    }

    @Test
    public void decryptBase64Test() throws IOException {

    
        String expect = "encryption standard";
        String privateKey = "Abqi601gS2dEzmek+oxa1Ee2RSs1S5J6byBJQYgOQYs=";
        String cipherText = "BBfuKdHktDEupJo9A1e1+nnMkayHZ2wmhV/5CSK8j0ESQhGOO0KEN+vxTfPDXOwnBHNA5tULLCg0VPzNxLv5rjhzwzyMoWLaHHRcEGxvBAlqaAJta+kXoeLx2slfrqONVcsvo1QnF5bap8AXFP3ZvVqx+K0=";
        SM2DecryptResult sm2DecryptResult = SM2Decrypt.decryptUseBase64(privateKey, cipherText);
        String plainText = new String(sm2DecryptResult.getPlainText());
        boolean c3Result = sm2DecryptResult.getC3Result();
        assertEquals(plainText, expect);
        assertTrue(c3Result);
    }


    @Test
    public void decryptBase64Test1() throws IOException {

       
        String privateKey = "TP7yiRhfWgkz+27M9/61bV6OVlTGjNRn7hoA1N8d5TI=";
        String cipherText = "BAw95FP4lGex8oMIGKNAJgeaqzsImnTlKxMWwIehdf5QHYibhO1EjZb/lBRZjthKn0vNSkFKPHYjdRkX1dUwmhfD457puVDCJ84eFLJY1mec13IQjaHyiGVPICvGyBz4XA3Cb6zMA7OmHw==";
        SM2DecryptResult sm2DecryptResult = SM2Decrypt.decryptUseBase64(privateKey, cipherText,true);
        String plainText = new String(sm2DecryptResult.getPlainText());
        System.out.println(plainText);


    }
}
