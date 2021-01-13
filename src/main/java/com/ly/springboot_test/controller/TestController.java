package com.ly.springboot_test.controller;

import com.ly.springboot_test.rsaUtil.Rsa;
import com.ly.springboot_test.rsaUtil.SignAlgorithm;
import net.sf.json.JSONObject;
import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.UnsupportedEncodingException;

@Controller
public class TestController {
    /**
     * 获取一键闪验登录手机号
     * @param request
     * @param response
     * @return
     * @throws ServletRequestBindingException
     */
    @ResponseBody
    @RequestMapping(value = "/getMobile", method = {RequestMethod.GET})
    public JSONObject getMobile(HttpServletRequest request, HttpServletResponse response) throws ServletRequestBindingException {

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
        String channel = ServletRequestUtils.getStringParameter(request, "channel");
        String platform = ServletRequestUtils.getStringParameter(request, "platform");
        String auth_code = ServletRequestUtils.getStringParameter(request, "auth_code");
        String token = ServletRequestUtils.getStringParameter(request, "token");
//        String auth_code="";
//        String channel="0";
//        String platform="0";
//        String token="STsid00000016099884088010Ywlzuy6pWmZOtw0xuWm99u6cNun5svd";
        //拼接要生成签名的数据
        JSONObject result = new JSONObject();
        String data = "app_key="+app_key+"&auth_code="+auth_code+"&channel="+channel+"&platform="+platform+"&token="+token;
        try {
            //生成签名
            String sign = Rsa.signHex(data, myPrivateKey, SignAlgorithm.SHA256withRSA);
            System.out.println("我的签名:" + sign);

            //请求linked ME平台
            //1.创建httpclient客户端
            CloseableHttpClient httpclient = HttpClientBuilder.create().build();
            //2.创建post请求
            String url = "https://account.linkedme.cc/phone/info";
            HttpPost post = new HttpPost(url);
            //3.组装请求参数
            JSONObject params = new JSONObject();
            params.put("app_key", app_key);
            params.put("auth_code", auth_code);
            params.put("channel", channel);
            params.put("platform", platform);
            params.put("token", token);
            params.put("sign", sign);
            //设置参数到请求对象中
            StringEntity stringEntity = new StringEntity(params.toString());
            post.setEntity(stringEntity);
            //4.设置请求头
            post.setHeader("Content-type", "application/json");
            //5.执行请求
            HttpResponse res = httpclient.execute(post);
            //6.解析响应结果
            HttpEntity entity = res.getEntity();
            String body = EntityUtils.toString(entity, "utf-8");
            System.out.println("linkedME响应结果: " + body);
            //7.解密返回的密文
            JSONObject jsonResBody = JSONObject.fromObject(body);
            JSONObject jsonResHeader = JSONObject.fromObject(jsonResBody.get("header"));
            if ("200".equals(jsonResHeader.get("code").toString())) {
                String mobile = (String) jsonResBody.get("body");
                mobile = Rsa.decryptHex(mobile, myPrivateKey);
                result.put("mobile",mobile);
                return CommonResp.wrapJson(result);
            }
            result.put("resBody",jsonResHeader);
            return CommonResp.wrapJson(result);
        } catch (ClientProtocolException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return CommonResp.wrapJson(result);
    }

}
