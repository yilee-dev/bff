package dh.bff.opensearch;

import tools.jackson.databind.ObjectMapper;
import io.netty.handler.ssl.SslContextBuilder;
import io.netty.handler.ssl.util.InsecureTrustManagerFactory;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.resources.ConnectionProvider;

import java.time.Duration;
import java.util.Base64;

@Configuration
@RequiredArgsConstructor
public class OpenSearchConfig {

    private final OpenSearchProperties props;

    @Bean
    @ConditionalOnMissingBean
    public ObjectMapper objectMapper() {
        return new ObjectMapper();
    }

    @Bean("openSearchWebClient")
    public WebClient openSearchWebClient() throws Exception {
        var sslContext = SslContextBuilder.forClient()
                .trustManager(InsecureTrustManagerFactory.INSTANCE)
                .build();

        var pool = ConnectionProvider.builder("opensearch")
                .maxConnections(50)
                .maxIdleTime(Duration.ofSeconds(30))
                .maxLifeTime(Duration.ofMinutes(4))
                .evictInBackground(Duration.ofSeconds(20))
                .build();

        var httpClient = HttpClient.create(pool)
                .secure(spec -> spec.sslContext(sslContext))
                .responseTimeout(Duration.ofMinutes(10));

        String auth = Base64.getEncoder()
                .encodeToString((props.getUsername() + ":" + props.getPassword()).getBytes());

        return WebClient.builder()
                .baseUrl(props.getUrl())
                .defaultHeader(HttpHeaders.AUTHORIZATION, "Basic " + auth)
                .defaultHeader(HttpHeaders.CONTENT_TYPE, "application/json")
                .clientConnector(new ReactorClientHttpConnector(httpClient))
                .codecs(config -> config.defaultCodecs().maxInMemorySize(100 * 1024 * 1024))
                .build();
    }
}
