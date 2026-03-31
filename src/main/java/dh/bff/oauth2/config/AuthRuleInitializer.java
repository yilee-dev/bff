package dh.bff.oauth2.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.stereotype.Component;

import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthRuleInitializer implements ApplicationRunner {

    private static final String AUTH_MAP_KEY = "AUTH_MAP";

    private final ReactiveRedisTemplate<String, String> redisTemplate;

    private static final Map<String, String> DEFAULT_RULES = Map.of(
            "GET:/api/v1/rental-pcs/**", "RENTALS_VIEWER",
            "POST:/api/v1/rental-pcs/**", "RENTALS_MANAGER",
            "PUT:/api/v1/rental-pcs/**", "RENTALS_MANAGER",
            "DELETE:/api/v1/rental-pcs/**", "RENTALS_MANAGER"
    );

    @Override
    public void run(ApplicationArguments args) {
        redisTemplate.opsForHash().size(AUTH_MAP_KEY)
                .flatMap(size -> {
                    if (size > 0) {
                        log.info("AUTH_MAP already has {} rules, skipping initialization", size);
                        return redisTemplate.opsForHash().entries(AUTH_MAP_KEY).then();
                    }

                    log.info("Initializing AUTH_MAP with {} default rules", DEFAULT_RULES.size());
                    return redisTemplate.opsForHash()
                            .putAll(AUTH_MAP_KEY, DEFAULT_RULES)
                            .then();
                })
                .subscribe();
    }
}
