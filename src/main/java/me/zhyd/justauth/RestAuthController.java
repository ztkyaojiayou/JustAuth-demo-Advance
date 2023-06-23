package me.zhyd.justauth;

import com.alibaba.fastjson.JSONObject;
import com.xkcoding.http.config.HttpConfig;
import lombok.extern.slf4j.Slf4j;
import me.zhyd.justauth.cache.AuthStateRedisCache;
import me.zhyd.justauth.custom.AuthMyGitlabRequest;
import me.zhyd.justauth.service.UserService;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.enums.scope.*;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.request.*;
import me.zhyd.oauth.utils.AuthScopeUtils;
import me.zhyd.oauth.utils.AuthStateUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.ModelAndView;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @version 1.0
 * @website https://www.zhyd.me
 * @date 2019/2/19 9:28
 * @since 1.8
 */
@Slf4j
@Controller
@RequestMapping("/oauth")
public class RestAuthController {

    @Autowired
    private AuthStateRedisCache stateRedisCache;
    @Autowired
    private UserService userService;

    /**
     * 生成授权页url
     * 目的：用于登录用户点击该url来完成第三方登录平台的授权
     * 具体的oauth授权流程也就是在这一步完成的，
     * 大致流程或原理为：
     * 当前用户点击该授权链接时，就会自动跳到第三方平台的授权页面，
     * 此时用户登录该平台（扫码或用户名密码登录）并点击授权按钮，
     * 之后第三方平台就会验证并通过下面的回调地址（我们需要事先在第三方平台上设置好）返回token给我们！
     * 具体就是我们通过AuthCallback类来接收第三方平台给我们的回调信息！！！
     * 拿到token后，我们就可以根据该token去请求第三方平台以获取该用户的基本信息啦！！！
     * （就是普通的http请求啦，而具体的请求url则就有该框架给我们封装好啦，这也是该框架的核心功能之一！！！）
     * <p>
     * 但以上流程我们在实际接入时并不需要关心！！！
     *
     * @param source
     * @param response
     * @throws IOException
     */
    @RequestMapping("/render/{source}")
    @ResponseBody
    public void renderAuth(@PathVariable("source") String source, HttpServletResponse response) throws IOException {
        log.info("进入render：" + source);
        //构造请求第三方登录平台url的请求链接
        AuthRequest authRequest = getAuthRequest(source);
        //获取授权地址
        String authorizeUrl = authRequest.authorize(AuthStateUtils.createState());
        log.info(authorizeUrl);
        //直接通过重定向返回给前端，供用户点击并授权第三方平台授权和登录
        response.sendRedirect(authorizeUrl);
    }

    /**
     * 接收回调
     * 也即授权成功后第三方平台通过调用该接口返回token，
     * 于是我们就可以根据该token去第三方平台请求获取该用户的基础信息啦！！！
     * 之后我们就可以将其进行存库或注册操作！！！
     * oauth平台中配置的授权回调地址，以本项目为例，在创建github授权应用时的回调地址应为：http://127.0.0.1:8443/oauth/callback/github
     */
    @RequestMapping("/callback/{source}")
    public ModelAndView login(@PathVariable("source") String source, AuthCallback callback,
                              HttpServletRequest request) {
        log.info("进入callback：" + source + " callback params：" + JSONObject.toJSONString(callback));
        AuthRequest authRequest = getAuthRequest(source);
        //根据token请求第三方平台以获取该用户的基本信息
        //因为这一步也可以大致理解为登录，因此这里使用login命名！！！
        AuthResponse<AuthUser> response = authRequest.login(callback);
        log.info(JSONObject.toJSONString(response));

        if (response.ok()) {
            //保存该用户信息（包含token）
            userService.save(response.getData());
            return new ModelAndView("redirect:/users");
        }

        Map<String, Object> map = new HashMap<>(1);
        map.put("errorMsg", response.getMsg());

        return new ModelAndView("error", map);
    }

    /**
     * 取消授权（部分平台支持）
     * 也即把已授权的账户的账户信息在我们的项目中删除！！！
     *
     * @param source 第三方平台类型
     * @param uuid   要取消授权的用户的uuid，也即该账户在第三方平台中的唯一标识
     * @return
     * @throws IOException
     */
    @RequestMapping("/revoke/{source}/{uuid}")
    @ResponseBody
    public Response revokeAuth(@PathVariable("source") String source, @PathVariable("uuid") String uuid) throws IOException {
        AuthRequest authRequest = getAuthRequest(source.toLowerCase());

        AuthUser user = userService.getByUuid(uuid);
        if (null == user) {
            return Response.error("用户不存在");
        }
        AuthResponse<AuthToken> response = null;
        try {
            response = authRequest.revoke(user.getToken());
            if (response.ok()) {
                userService.remove(user.getUuid());
                return Response.success("用户 [" + user.getUsername() + "] 的 授权状态 已收回！");
            }
            return Response.error("用户 [" + user.getUsername() + "] 的 授权状态 收回失败！" + response.getMsg());
        } catch (AuthException e) {
            return Response.error(e.getErrorMsg());
        }
    }

    /**
     * 刷新token（部分平台支持）
     * 也即重新请求一次token信息并刷新原信息
     *
     * @param source
     * @param uuid   要刷新token的用户的uuid
     * @return
     */
    @RequestMapping("/refresh/{source}/{uuid}")
    @ResponseBody
    public Object refreshAuth(@PathVariable("source") String source, @PathVariable("uuid") String uuid) {
        AuthRequest authRequest = getAuthRequest(source.toLowerCase());
//获取该账户在本项目中原存储的信息
        AuthUser user = userService.getByUuid(uuid);
        if (null == user) {
            return Response.error("用户不存在");
        }
        AuthResponse<AuthToken> response = null;
        try {
            //重写获取/请求token信息
            //注意：这里就只返回了token信息，而不再返回基本信息，因为已经有了呀！！！
            response = authRequest.refresh(user.getToken());
            if (response.ok()) {
                //刷新token信息
                user.setToken(response.getData());
                //再存入redis
                userService.save(user);
                return Response.success("用户 [" + user.getUsername() + "] 的 access token 已刷新！新的 accessToken: " + response.getData().getAccessToken());
            }
            return Response.error("用户 [" + user.getUsername() + "] 的 access token 刷新失败！" + response.getMsg());
        } catch (AuthException e) {
            return Response.error(e.getErrorMsg());
        }
    }

    /**
     * 根据具体的授权来源，获取授权请求工具类
     *
     * @param source
     * @return
     */
    private AuthRequest getAuthRequest(String source) {
        AuthRequest authRequest = null;
        switch (source.toLowerCase()) {
            case "dingtalk":
                authRequest = new AuthDingTalkRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/dingtalk")
                        .build());
                break;
            case "baidu":
                authRequest = new AuthBaiduRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/baidu")
                        .scopes(Arrays.asList(
                                AuthBaiduScope.BASIC.getScope(),
                                AuthBaiduScope.SUPER_MSG.getScope(),
                                AuthBaiduScope.NETDISK.getScope()
                        ))
//                        .clientId("")
//                        .clientSecret("")
//                        .redirectUri("http://localhost:9001/oauth/baidu/callback")
                        .build());
                break;
            case "github":
                authRequest = new AuthGithubRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/github")
                        .scopes(AuthScopeUtils.getScopes(AuthGithubScope.values()))
                        // 针对国外平台配置代理
                        .httpConfig(HttpConfig.builder()
                                .timeout(15000)
                                .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 10080)))
                                .build())
                        .build(), stateRedisCache);
                break;
            case "gitee":
                authRequest = new AuthGiteeRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://127.0.0.1:8443/oauth/callback/gitee")
                        .scopes(AuthScopeUtils.getScopes(AuthGiteeScope.values()))
                        .build(), stateRedisCache);
                break;
            case "weibo":
                authRequest = new AuthWeiboRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://dblog-web.zhyd.me/oauth/callback/weibo")
                        .scopes(Arrays.asList(
                                AuthWeiboScope.EMAIL.getScope(),
                                AuthWeiboScope.FRIENDSHIPS_GROUPS_READ.getScope(),
                                AuthWeiboScope.STATUSES_TO_ME_READ.getScope()
                        ))
                        .build());
                break;
            case "coding":
                authRequest = new AuthCodingRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://dblog-web.zhyd.me/oauth/callback/coding")
                        .domainPrefix("")
                        .scopes(Arrays.asList(
                                AuthCodingScope.USER.getScope(),
                                AuthCodingScope.USER_EMAIL.getScope(),
                                AuthCodingScope.USER_PHONE.getScope()
                        ))
                        .build());
                break;
            case "oschina":
                authRequest = new AuthOschinaRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/oschina")
                        .build());
                break;
            case "alipay":
                // 支付宝在创建回调地址时，不允许使用localhost或者127.0.0.1，所以这儿的回调地址使用的局域网内的ip
                authRequest = new AuthAlipayRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .alipayPublicKey("")
                        .redirectUri("https://www.zhyd.me/oauth/callback/alipay")
                        .build());
                break;
            case "qq":
                authRequest = new AuthQqRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/qq")
                        .build());
                break;
            case "wechat_open":
                authRequest = new AuthWeChatOpenRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://www.zhyd.me/oauth/callback/wechat")
                        .build());
                break;
            case "csdn":
                authRequest = new AuthCsdnRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://dblog-web.zhyd.me/oauth/callback/csdn")
                        .build());
                break;
            case "taobao":
                authRequest = new AuthTaobaoRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://dblog-web.zhyd.me/oauth/callback/taobao")
                        .build());
                break;
            case "google":
                authRequest = new AuthGoogleRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/google")
                        .scopes(AuthScopeUtils.getScopes(AuthGoogleScope.USER_EMAIL, AuthGoogleScope.USER_PROFILE,
                                AuthGoogleScope.USER_OPENID))
                        // 针对国外平台配置代理
                        .httpConfig(HttpConfig.builder()
                                .timeout(15000)
                                .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 10080)))
                                .build())
                        .build());
                break;
            case "facebook":
                authRequest = new AuthFacebookRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("https://justauth.cn/oauth/callback/facebook")
                        .scopes(AuthScopeUtils.getScopes(AuthFacebookScope.values()))
                        // 针对国外平台配置代理
                        .httpConfig(HttpConfig.builder()
                                .timeout(15000)
                                .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 10080)))
                                .build())
                        .build());
                break;
            case "douyin":
                authRequest = new AuthDouyinRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://dblog-web.zhyd.me/oauth/callback/douyin")
                        .build());
                break;
            case "linkedin":
                authRequest = new AuthLinkedinRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/linkedin")
                        .scopes(null)
                        .build());
                break;
            case "microsoft":
                authRequest = new AuthMicrosoftRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/microsoft")
                        .scopes(Arrays.asList(
                                AuthMicrosoftScope.USER_READ.getScope(),
                                AuthMicrosoftScope.USER_READWRITE.getScope(),
                                AuthMicrosoftScope.USER_READBASIC_ALL.getScope(),
                                AuthMicrosoftScope.USER_READ_ALL.getScope(),
                                AuthMicrosoftScope.USER_READWRITE_ALL.getScope(),
                                AuthMicrosoftScope.USER_INVITE_ALL.getScope(),
                                AuthMicrosoftScope.USER_EXPORT_ALL.getScope(),
                                AuthMicrosoftScope.USER_MANAGEIDENTITIES_ALL.getScope(),
                                AuthMicrosoftScope.FILES_READ.getScope()
                        ))
                        .build());
                break;
            case "mi":
                authRequest = new AuthMiRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://dblog-web.zhyd.me/oauth/callback/mi")
                        .build());
                break;
            case "toutiao":
                authRequest = new AuthToutiaoRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://dblog-web.zhyd.me/oauth/callback/toutiao")
                        .build());
                break;
            case "teambition":
                authRequest = new AuthTeambitionRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://127.0.0.1:8443/oauth/callback/teambition")
                        .build());
                break;
            case "pinterest":
                authRequest = new AuthPinterestRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("https://eadmin.innodev.com.cn/oauth/callback/pinterest")
                        // 针对国外平台配置代理
                        .httpConfig(HttpConfig.builder()
                                .timeout(15000)
                                .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 10080)))
                                .build())
                        .build());
                break;
            case "renren":
                authRequest = new AuthRenrenRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://127.0.0.1:8443/oauth/callback/teambition")
                        .build());
                break;
            case "stack_overflow":
                authRequest = new AuthStackOverflowRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("((")
                        .redirectUri("http://localhost:8443/oauth/callback/stack_overflow")
                        .stackOverflowKey("")
                        .build());
                break;
            case "huawei":
                authRequest = new AuthHuaweiRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://127.0.0.1:8443/oauth/callback/huawei")
                        .scopes(Arrays.asList(
                                AuthHuaweiScope.BASE_PROFILE.getScope(),
                                AuthHuaweiScope.MOBILE_NUMBER.getScope(),
                                AuthHuaweiScope.ACCOUNTLIST.getScope(),
                                AuthHuaweiScope.SCOPE_DRIVE_FILE.getScope(),
                                AuthHuaweiScope.SCOPE_DRIVE_APPDATA.getScope()
                        ))
                        .build());
                break;
            case "wechat_enterprise":
                authRequest = new AuthWeChatEnterpriseQrcodeRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://justauth.cn/oauth/callback/wechat_enterprise")
                        .agentId("1000003")
                        .build());
                break;
            case "kujiale":
                authRequest = new AuthKujialeRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://dblog-web.zhyd.me/oauth/callback/kujiale")
                        .build());
                break;
            case "gitlab":
                authRequest = new AuthGitlabRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/gitlab")
                        .scopes(AuthScopeUtils.getScopes(AuthGitlabScope.values()))
                        .build());
                break;
            case "meituan":
                authRequest = new AuthMeituanRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/meituan")
                        .build());
                break;
            case "eleme":
                authRequest = new AuthElemeRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://dblog-web.zhyd.me/oauth/callback/eleme")
                        .build());
                break;
            case "mygitlab":
                authRequest = new AuthMyGitlabRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://127.0.0.1:8443/oauth/callback/mygitlab")
                        .build());
                break;
            case "twitter":
                authRequest = new AuthTwitterRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("https://threelogin.31huiyi.com/oauth/callback/twitter")
                        // 针对国外平台配置代理
                        .httpConfig(HttpConfig.builder()
                                .timeout(15000)
                                .proxy(new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", 10080)))
                                .build())
                        .build());
                break;
            case "wechat_mp":
                authRequest = new AuthWeChatMpRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("")
                        .build());
                break;
            case "aliyun":
                authRequest = new AuthAliyunRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/aliyun")
                        .build());
                break;
            case "xmly":
                authRequest = new AuthXmlyRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/xmly")
                        .build());
                break;
            case "feishu":
                authRequest = new AuthFeishuRequest(AuthConfig.builder()
                        .clientId("")
                        .clientSecret("")
                        .redirectUri("http://localhost:8443/oauth/callback/feishu")
                        .build());
                break;
            default:
                break;
        }
        if (null == authRequest) {
            throw new AuthException("未获取到有效的Auth配置");
        }
        return authRequest;
    }
}
