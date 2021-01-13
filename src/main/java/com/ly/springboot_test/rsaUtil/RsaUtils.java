package com.ly.springboot_test.rsaUtil;


import org.apache.commons.collections4.MapUtils;
import org.apache.commons.lang3.StringUtils;


import java.util.Map;
import java.util.TreeMap;

/**
 *
 */
public class RsaUtils {

    /**
     * 获取签名
     *
     * @param paramsTreeMap TreeMap数据结构的参数集
     * @param privateKey    私钥
     * @return 签名数据
     */
    public static String getHexSign(Map<String, String> paramsTreeMap, String privateKey) {
        String verifySignResult = null;

        if (MapUtils.isEmpty(paramsTreeMap) || StringUtils.isEmpty(privateKey)) {
            return verifySignResult;
        }

        Map<String, String> treeMap = new TreeMap<>(paramsTreeMap);

        StringBuilder stringBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : treeMap.entrySet()) {
            stringBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        }
        String paramsStr = stringBuilder.toString();
        paramsStr = paramsStr.substring(0, paramsStr.length() - 1);

        try {
            verifySignResult = Rsa.signHex(paramsStr, privateKey, SignAlgorithm.SHA256withRSA);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return verifySignResult;
    }

    /**
     * 校验签名
     *
     * @param paramsTreeMap TreeMap数据结构的参数集
     * @param publicKey     公钥
     * @param sign          签名
     * @return true: 校验成功 false: 校验失败
     */
    public static boolean verifyHexSign(Map<String, String> paramsTreeMap, String publicKey, String sign) {
        boolean verifyResult = false;

        if (MapUtils.isEmpty(paramsTreeMap) || StringUtils.isEmpty(publicKey) || StringUtils.isEmpty(sign)) {
            return verifyResult;
        }

        Map<String, String> treeMap = new TreeMap<>(paramsTreeMap);

        StringBuilder stringBuilder = new StringBuilder();
        for (Map.Entry<String, String> entry : treeMap.entrySet()) {
            stringBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        }
        String paramsStr = stringBuilder.toString();
        paramsStr = paramsStr.substring(0, paramsStr.length() - 1);
        try {
            verifyResult = Rsa.verifyHex(paramsStr, publicKey, sign, SignAlgorithm.SHA256withRSA);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return verifyResult;
    }

    /**
     * 公钥加密
     *
     * @param sourceData   需要加密的数据
     * @param publicKeyStr 公钥
     * @return 加密后的数据
     */
    public static String encryptHexData(String sourceData, String publicKeyStr) {
        try {
            return Rsa.encryptHex(sourceData, publicKeyStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * 私钥解密
     *
     * @param encodeData    需要解密的数据
     * @param privateKeyStr 私钥
     * @return 解密后的数据
     */
    public static String decryptHexData(String encodeData, String privateKeyStr) {
        try {
            return Rsa.decryptHex(encodeData, privateKeyStr);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public static void main(String[] args) {

    }
}
