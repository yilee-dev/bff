package dh.bff.opensearch;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Data
@Component
@ConfigurationProperties(prefix = "opensearch")
public class OpenSearchProperties {
    private String url;
    private String username;
    private String password;
    private String index;
}
