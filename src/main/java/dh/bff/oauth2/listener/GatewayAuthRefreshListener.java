package dh.bff.oauth2.listener;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.data.redis.connection.ReactiveSubscription;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.listener.ChannelTopic;
import org.springframework.stereotype.Component;

@Component
@RequiredArgsConstructor
public class GatewayAuthRefreshListener implements CommandLineRunner {

    private final ReactiveStringRedisTemplate redisTemplate;

    @Override
    public void run(String... args) throws Exception {
        redisTemplate.listenTo(ChannelTopic.of("auth-refresh-channel"))
                .map(ReactiveSubscription.Message::getMessage)
                .subscribe(message -> {
                    //
                });
    }
}
