package dh.bff.oauth2.config;

import dh.bff.constant.ClientInfo;
import dh.bff.oauth2.filter.CsrfTokenResponseHeaderFilter;
import dh.bff.oauth2.handler.CustomLoginSuccessHandler;
import dh.bff.oauth2.handler.CustomLogoutSuccessHandler;
import dh.bff.oauth2.repository.OriginPreservingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final OriginPreservingRepository originPreservingRepository;
    private final ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityWebFilterChain gatewaySecurityWebFilterChain(ServerHttpSecurity http) {
        CookieServerCsrfTokenRepository cookieServerCsrfTokenRepository = new CookieServerCsrfTokenRepository();
        cookieServerCsrfTokenRepository.setCookieCustomizer(cookie ->
                cookie.httpOnly(true)
                        .secure(false)
                        .sameSite(null));

        return http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(cookieServerCsrfTokenRepository)
                        .requireCsrfProtectionMatcher(exchange -> {
                            return ServerWebExchangeMatchers.pathMatchers(HttpMethod.POST, "/logout")
                                    .matches(exchange)
                                    .flatMap(matchResult -> matchResult.isMatch() ?
                                            ServerWebExchangeMatcher.MatchResult.notMatch() :
                                            CsrfWebFilter.DEFAULT_CSRF_MATCHER.matches(exchange));
                        }))
                .addFilterAfter(new CsrfTokenResponseHeaderFilter(), SecurityWebFiltersOrder.CSRF)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/login/**", "/public/**", "/logout", "/logout/**").permitAll()
                        .anyExchange().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .authenticationSuccessHandler(new CustomLoginSuccessHandler()))
                .requestCache(cache -> cache
                        .requestCache(new WebSessionServerRequestCache()))
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessHandler(new CustomLogoutSuccessHandler(clientRegistrationRepository))
                )
                .build();
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsWebFilter() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowedHeaders(List.of("*"));
        corsConfiguration.setAllowedOrigins(List.of(ClientInfo.getClientInfo()));

        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
        return urlBasedCorsConfigurationSource;
    }
}
