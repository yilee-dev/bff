package dh.bff.oauth2.config;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
@ConfigurationProperties(prefix = "app.auth")
@Getter
@Setter
public class AuthRuleProperties {

    private List<RuleEntry> defaultRules = new ArrayList<>();

    @Getter
    @Setter
    public static class RuleEntry {
        private String method;
        private String path;
        private String authority;

        /** Redis 해시 키: METHOD:PATH */
        public String toRedisKey() {
            return method.toUpperCase() + ":" + path;
        }
    }
}
