package com.sm.sm2;

import com.sm.SMUtils;
import com.sm.sm3.SM3;
import org.bouncycastle.math.ec.ECPoint;

import java.io.IOException;
import java.math.BigInteger;

/**
 * SM2签名验签
 *
 * @author William Sun
 */
public class SM2Verify {


    public static boolean verify(SM2VerifyParams sm2VerifyParams) throws IOException {
        return verify(sm2VerifyParams, false);
    }

  
    public static boolean verify(SM2VerifyParams sm2VerifyParams, boolean onlineEnv) throws IOException {

        byte[] userId = sm2VerifyParams.getUserId();
        byte[] publicKey = sm2VerifyParams.getPublicKey();
        byte[] sourceData = sm2VerifyParams.getSourceData();
        SM2SignResult sm2SignResult = sm2VerifyParams.getSm2SignResult();
        SM2 sm2 = new SM2(onlineEnv);
        ECPoint pubKey = sm2.eccCurve.decodePoint(publicKey);
        byte[] z = SMUtils.sm2GetZ(userId, pubKey, sm2);
        byte[] M = new byte[z.length + sourceData.length];
        System.arraycopy(z, 0, M, 0, z.length);
        System.arraycopy(sourceData, 0, M, z.length, sourceData.length);
        byte[] e = SM3.hash(M);
        return doVerify(e, pubKey, sm2SignResult, sm2);
    }
    private static boolean doVerify(byte md[], ECPoint publicKey, SM2SignResult sm2SignResult, SM2 sm2) {

        BigInteger e = new BigInteger(1, md);
        BigInteger r = sm2SignResult.getR();
        BigInteger s = sm2SignResult.getS();
        BigInteger t = r.add(s).mod(sm2.getEcc_n());
        if (t.equals(BigInteger.ZERO)) {
            return false;
        } else {
            ECPoint x1y1 = sm2.getEcc_point_g().multiply(s);
            x1y1 = x1y1.add(publicKey.multiply(t));
            BigInteger R = e.add(x1y1.normalize().getXCoord().toBigInteger()).mod(sm2.getEcc_n());
            return r.equals(R);

        }
    }
}
