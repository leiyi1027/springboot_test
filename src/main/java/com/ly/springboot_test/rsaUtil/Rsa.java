package com.ly.springboot_test.rsaUtil;

import net.sf.json.JSONObject;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.Header;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;

import javax.crypto.Cipher;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Rsa {

    public static final String ENTER = "\\n";

    /**
     * 获取密钥对
     *
     * @return 密钥对
     */
    public static KeyPair getKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(1024);
        return generator.generateKeyPair();
    }

    /**
     * 获取私钥
     *
     * @param privateKey 私钥字符串
     * @return
     */
    private static PrivateKey getPrivateKey(String privateKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.getDecoder().decode(privateKey.getBytes());
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decodedKey);
        return keyFactory.generatePrivate(keySpec);
    }

    /**
     * 获取公钥
     *
     * @param publicKey 公钥字符串
     * @return
     */
    private static PublicKey getPublicKey(String publicKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        byte[] decodedKey = Base64.getDecoder().decode(publicKey.getBytes());
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decodedKey);

        return keyFactory.generatePublic(keySpec);
    }

    /**
     * 根据对应算法加密
     *
     * @param data      待加密数据
     * @param publicKey 公钥
     * @param algorithm 算法
     * @return
     * @throws Exception
     */
    public static String encryptHexWithAlgorithm(String data, String publicKey, String algorithm) throws Exception {
        if (publicKey == null || StringUtils.isEmpty(data)) {
            throw new Exception("加密公钥为空, 请设置");
        }
        publicKey = publicKey.replaceAll(ENTER, StringUtils.EMPTY);
        PublicKey rsaPublicKey = getPublicKey(publicKey);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, rsaPublicKey);
        byte[] plainTextData = data.getBytes();
        byte[] output = cipher.doFinal(plainTextData);
        return byte2hex(output);

    }

    /**
     * RSA公钥加密
     *
     * @param str       加密字符串
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String encrypt(String str, String publicKey) throws Exception {
        publicKey = publicKey.replaceAll(ENTER, StringUtils.EMPTY);
        //base64编码的公钥
        byte[] decoded = Base64.getDecoder().decode(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return Base64.getEncoder().encodeToString(cipher.doFinal(str.getBytes("UTF-8")));
    }


    /**
     * RSA公钥加密
     *
     * @param str       加密字符串
     * @param publicKey 公钥
     * @return 密文
     * @throws Exception 加密过程中的异常信息
     */
    public static String encryptHex(String str, String publicKey) throws Exception {
        publicKey = publicKey.replaceAll(ENTER, StringUtils.EMPTY);
        //base64编码的公钥
        byte[] decoded = Base64.getDecoder().decode(publicKey);
        RSAPublicKey pubKey = (RSAPublicKey) KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
        //RSA加密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return byte2hex(cipher.doFinal(str.getBytes("UTF-8")));
    }
    /**
     * RSA私钥解密
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decrypt(String str, String privateKey) throws Exception {
        privateKey = privateKey.replaceAll(ENTER, StringUtils.EMPTY);
        //64位解码加密后的字符串
        byte[] inputByte = Base64.getDecoder().decode(str);
        //base64编码的私钥
        byte[] decoded = Base64.getDecoder().decode(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return new String(cipher.doFinal(inputByte));
    }


    /**
     * RSA私钥解密
     *
     * @param str        加密字符串
     * @param privateKey 私钥
     * @return 明文
     * @throws Exception 解密过程中的异常信息
     */
    public static String decryptHex(String str, String privateKey) throws Exception {
        privateKey = privateKey.replaceAll(ENTER, StringUtils.EMPTY);
        //64位解码加密后的字符串
        byte[] inputByte = hexStr2byte(str);
        //base64编码的私钥
//        byte[] decoded = Base64.getDecoder().decode(privateKey);
        byte[] decoded = org.apache.commons.codec.binary.Base64.decodeBase64(privateKey);
        RSAPrivateKey priKey = (RSAPrivateKey) KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(decoded));
        //RSA解密
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, priKey);
        return new String(cipher.doFinal(inputByte));
    }

    /**
     * 签名
     *
     * @param data       待签名数据
     * @param privateKey 私钥
     * @return 签名
     */
    public static String sign(String data, String privateKey, SignAlgorithm signAlgorithm) throws Exception {
        privateKey = privateKey.replaceAll(ENTER, StringUtils.EMPTY);
        byte[] signData = sign(data.getBytes(), privateKey, signAlgorithm);
        return Base64.getEncoder().encodeToString(signData);
    }

    public static String signHex(String data, String privateKey, SignAlgorithm signAlgorithm) throws Exception {
        privateKey = privateKey.replaceAll(ENTER, StringUtils.EMPTY);
        byte[] signData = sign(data.getBytes(), privateKey, signAlgorithm);
        return byte2hex(signData);
    }

    public static byte[] sign(byte[] data, String privateKey, SignAlgorithm signAlgorithm) throws Exception {
        privateKey = privateKey.replaceAll(ENTER, StringUtils.EMPTY);
        PrivateKey priKey = getPrivateKey(privateKey);
        Signature signature = Signature.getInstance(signAlgorithm.getAlgorithm());
        signature.initSign(priKey);
        signature.update(data);
        return signature.sign();
    }


    /**
     * 验签
     *
     * @param srcData   原始字符串
     * @param publicKey 公钥
     * @param sign      签名
     * @return 是否验签通过
     */
    public static boolean verify(String srcData, String publicKey, String sign, SignAlgorithm signAlgorithm) throws Exception {
        publicKey = publicKey.replaceAll(ENTER, StringUtils.EMPTY);
        return verify(srcData.getBytes(), publicKey, Base64.getDecoder().decode(sign), signAlgorithm);
    }

    public static boolean verifyHex(String srcData, String publicKey, String sign, SignAlgorithm signAlgorithm) throws Exception {
        publicKey = publicKey.replaceAll(ENTER, StringUtils.EMPTY);
        return verify(srcData.getBytes(), publicKey, hexStr2byte(sign), signAlgorithm);
    }

    public static boolean verify(byte[] srcData, String publicKey, byte[] sign, SignAlgorithm signAlgorithm) throws Exception {
        publicKey = publicKey.replaceAll(ENTER, StringUtils.EMPTY);
        PublicKey pubKey = getPublicKey(publicKey);
        Signature signature = Signature.getInstance(signAlgorithm.getAlgorithm());
        signature.initVerify(pubKey);
        signature.update(srcData);
        return signature.verify(sign);
    }

    /**
     * Description：将二进制转换成16进制字符串
     *
     * @param b
     * @return String
     * @author name：
     */
    private static String byte2hex(byte[] b) {
        String hs = "";
        String stmp = "";
        for (int n = 0; n < b.length; n++) {
            stmp = (Integer.toHexString(b[n] & 0XFF));
            if (stmp.length() == 1) {
                hs = hs + "0" + stmp;
            } else {
                hs = hs + stmp;
            }
        }
        return hs.toUpperCase();
    }

    /**
     * Description：将十六进制的字符串转换成字节数据
     *
     * @param strhex
     * @return byte[]
     * @author name：
     */
    private static byte[] hexStr2byte(String strhex) {
        if (strhex == null) {
            return null;
        }
        int l = strhex.length();
        if (l % 2 == 1) {
            return null;
        }
        byte[] b = new byte[l / 2];
        for (int i = 0; i != l / 2; i++) {
            b[i] = (byte) Integer.parseInt(strhex.substring(i * 2, i * 2 + 2), 16);
        }
        return b;
    }

    public static void main(String[] args) {
        try {

            String publicKey = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0PZZAbTqhPhmp9oILXQHyyWxxFIU6g+hu3YpMBozC75ZZcecZL+sw6p/BonHkP9qDPX2Z7rEIgCIpevbi+CA3enIFghN7WdTHf+ALSiYIk87WXUGfa2y55nQUzInDwJG4cADZ4moYXG3gfBtAqibbI3OMz5MqZa7gbdhtv1kw6wIDAQAB";
            String privateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBALQ9lkBtOqE+Gan2\n" +
                    "ggtdAfLJbHEUhTqD6G7dikwGjMLvlllx5xkv6zDqn8GiceQ/2oM9fZnusQiAIil6\n" +
                    "9uL4IDd6cgWCE3tZ1Md/4AtKJgiTztZdQZ9rbLnmdBTMicPAkbhwANniahhcbeB8\n" +
                    "G0CqJtsjc4zPkyplruBt2G2/WTDrAgMBAAECgYEArEdZwIcnTUwAV9bJgncKD7i7\n" +
                    "sHJ+zembV6zmLbjs/r7nJOOckxScZ4s73GebGSJ3iI5T6bie+pMPFDr2lQe6MfHI\n" +
                    "bhend4IhQA+q4Gh38zp0BPmepiPjXqQwezvuFBBJ1cCr4SYD2hqx0OVnyC3sA7LR\n" +
                    "eKyuAnKCzh0qcR6aSQECQQDjWlFzrW2d6LzNkuLzo5I9+8ZqWGc/yh6x2R67ZznU\n" +
                    "PE53hoM3smAig9qrlQtjoHfRgP53wMAug+RN+wDcSFtBAkEAyvOTyYXgUONLoXGm\n" +
                    "0PZlOgNrLIscjNwxsDUfY96C5pR4x1+Yh18kyJLScp3v8QWb5Kfgoe1492bgkFQ9\n" +
                    "x3udKwJAA9RxqtExF4fkJlJjIFeRDxo+rWvv0VNGURinO+DxSHH7oGfTrgyDMhGm\n" +
                    "jV1lY7hATHcv0jSdCCuQnP+tdAiEAQJBAJwVDBm2TjenNukooOSgOmWNb4VIT2K9\n" +
                    "jbE4ibWi0QVINkMO8B1cPMvMrvDbKkcwyx3lRksCeT+77QTS5Nhf5xUCQDJLuaZP\n" +
                    "STnoq/9SN9ux+o7Dnrc8SzMYTwCJj+/qCWOMjiRGs5TknWRB0tDjG5ioEtutvZ3o\n" +
                    "FeRhepsyYaII2h0=";

//            String data = "app_key=7e289a2484f4368dbafbd1e5c7d06903&extend=linkedme&recipient=+8618123972798&sign_name=短信&status_callback_url=http://requestbin.fullcontact.com/scvavdsc&template_id=110233&template_params=14,李月,2019/12/12,12:18";
            String myPublicKey ="MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC9xSphxKyC0DbfqcC+LJl/judA\n" +
                    "cOc4eoWVRsFGeDF+tdEYOW/ElQ8OJhVEz29tEUbjFPCz8BcrDyQfAVAiu2xVfT4p\n" +
                    "pTAyCVyolhczMrO3JO/GDD6JFB9/croiYka1bJnMfcT7IdUUiUmwnzxFRZs3QYQT\n" +
                    "0Y7KFkS7JJHYwiY84QIDAQAB";
            String myPrivateKey = "MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAL3FKmHErILQNt+p\n" +
                    "wL4smX+O50Bw5zh6hZVGwUZ4MX610Rg5b8SVDw4mFUTPb20RRuMU8LPwFysPJB8B\n" +
                    "UCK7bFV9PimlMDIJXKiWFzMys7ck78YMPokUH39yuiJiRrVsmcx9xPsh1RSJSbCf\n" +
                    "PEVFmzdBhBPRjsoWRLskkdjCJjzhAgMBAAECgYEAt37QrlzIGm1OwhKYZsslWaxK\n" +
                    "e4swaPI//Mm/1W4fHdCc8HmJU2J2fk3gvvp9Wc8c5jK3VKZRILexS7GvVQY5hvz+\n" +
                    "Vt8B9kIJRshCWm2tQRfgVluvio6D53587js3iP5+CRaGrQY4s1IbGYh9E2kWPUry\n" +
                    "Sh+wGuBKrizzQItjIuECQQDtNI2ATAm2AsTniTQuKzzb/Jm2H6ZUkHNsA+/J9159\n" +
                    "Ha8+oOSeQuSDnOStDJGweymf/xlz9Bx9hLf7uMNXonpFAkEAzM5xrkOg1PLfPW/G\n" +
                    "o3upEafnP4v9owD8CQVPPH67uC8w0jKPaZagBoWKJ/QCo90azcn06413PnquE1OQ\n" +
                    "Nt0P7QJAXEFRO3HXYQvIq0iIm+BDJkgjPFso5MDds0gAretgu4adDt2irQ7VM38E\n" +
                    "zW0TCLGOKeUccCWkIwlISUW968qMhQJBAMrg1gviQjewPyQEzai0ns42nQR+EEqg\n" +
                    "dwoYkF1EzX+uf5Y5L4dRBkRvlGPve44HQL4KCOwtvqnNrRLH/FvcsCECQGyNv0SZ\n" +
                    "ssemOLZI2B4u8FqD5//N+6rb3pbLm65ls9ey3rTF8cvRGS8c4YjviMON7BaY/WFt\n" +
                    "uaxfb5T6DzI9pV0=";
            String app_key="de76003d00f848301e78fe1d1c94534f";
            String auth_code="";
            String channel="0";
            String platform="1";
            String token="STsid00000016104442083115udhDWTumbwgEA0wLiqCFIXmnvmWDIvf";
            String data = "app_key="+app_key+"&auth_code="+auth_code+"&channel="+channel+"&platform="+platform+"&token="+token;
//          String data = "app_key=7e289a2484f4368dbafbd1e5c7d06903&extend=linkedme&recipient=+8618123972798&sign_name=短信&status_callback_url=http://requestbin.fullcontact.com/scvavdsc&template_id=110233&template_params=14,李月,2019/12/12,12:18";

            //生成签名
            String sign = Rsa.signHex(data, myPrivateKey, SignAlgorithm.SHA256withRSA);
            System.out.println("我的签名:"+sign);


            //请求linked ME平台
            //1.创建httpclient客户端
            CloseableHttpClient httpclient = HttpClientBuilder.create().build();
            //2.创建post请求
            String url = "https://account.linkedme.cc/phone/info";
            HttpPost post = new HttpPost(url);
            //3.组装请求参数
            JSONObject params = new JSONObject();
            params.put("app_key",app_key);
            params.put("auth_code",auth_code);
            params.put("channel",channel);
            params.put("platform",platform);
            params.put("token",token);
            params.put("sign",sign);
            //设置参数到请求对象中
            StringEntity stringEntity = new StringEntity(params.toString());
            post.setEntity(stringEntity);
            //4.设置请求头
            post.setHeader("Content-type","application/json");
            //5.执行请求
            HttpResponse res = httpclient.execute(post);
            //6.解析响应结果
            HttpEntity entity = res.getEntity();
            String body = EntityUtils.toString(entity, "utf-8");
            System.out.println("body: "+body);
            //7.解密返回的密文
            JSONObject jsonResBody = JSONObject.fromObject(body);
            JSONObject jsonResHeader = JSONObject.fromObject(jsonResBody.get("header"));
            if("200".equals(jsonResHeader.get("code"))) {
                String mobile = (String) jsonResBody.get("body");
                mobile = Rsa.decryptHex(mobile, myPrivateKey);
                System.out.println("手机号"+mobile);
            }
            //验证签名
//            boolean flag = Rsa.verifyHex(data, myPublicKey, sign, SignAlgorithm.SHA256withRSA);
//            System.out.println(flag);
//            //公钥加密手机号
//            String encryptHex = Rsa.encryptHex(String.valueOf(18361247971L), myPublicKey);
//            System.out.println(encryptHex);
//            //私钥解密手机号
            System.out.println(Rsa.decryptHex("4795068D07E10D945B35AF60B93F46997761D6C47C39938672739E7458C91CF69FCEEF78C88B67F4E8540F36293E5F9EE075D1E11774F3241989537F4FF101501283D5A337764BB232CD98F0FC56279EAEBB75B7475AFE2EB6390E54CD5E00E0D591AD904CE2CD57C9AD72E3C8801EDCB6B28C56763B1A1C96AF8F52213A3DF0", myPrivateKey));
        } catch (Exception e) {
            e.printStackTrace();
            System.out.print("加解密异常");
        }
    }
}