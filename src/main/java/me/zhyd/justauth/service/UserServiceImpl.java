package me.zhyd.justauth.service;

import com.alibaba.fastjson.JSONObject;
import me.zhyd.oauth.model.AuthUser;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.BoundHashOperations;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.LinkedList;
import java.util.List;
import java.util.Objects;

/**
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @version 1.0.0
 * @date 2020/6/27 22:41
 * @since 1.0.0
 */
@Service
public class UserServiceImpl implements UserService {

    @Autowired
    private RedisTemplate redisTemplate;

    //也是用于操作hash类型的redis操作类，该操作类需要先定义key，之后的put和get操作就都是filed中的key和value了！！！
    private BoundHashOperations<String, String, AuthUser> valueOperations;

    /**
     * 先定义key！！！
     */
    @PostConstruct
    public void init() {
        valueOperations = redisTemplate.boundHashOps("JUSTAUTH::USERS");
    }

    @Override
    public AuthUser save(AuthUser user) {
        //存储用户信息到redis中，这里的key和value属于filed了，都是隶属于上述已定义好的key下的！！！
        valueOperations.put(user.getUuid(), user);
        return user;
    }

    @Override
    public AuthUser getByUuid(String uuid) {
        //由于已经配置/替换了全局的redis序列化器，因此其实可以直接使用AuthUser接收！！！
        Object user = valueOperations.get(uuid);
        if (null == user) {
            return null;
        }
        //其实没有必要，直接就可以被反序列化成目标对象AuthUser
        return JSONObject.parseObject(JSONObject.toJSONString(user), AuthUser.class);
    }

    @Override
    public List<AuthUser> listAll() {
        return new LinkedList<>(Objects.requireNonNull(valueOperations.values()));
    }

    @Override
    public void remove(String uuid) {
        valueOperations.delete(uuid);
    }
}
