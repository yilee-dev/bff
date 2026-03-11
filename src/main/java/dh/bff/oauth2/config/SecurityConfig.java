package dh.bff.oauth2.config;

import dh.bff.constant.ClientInfo;
import dh.bff.oauth2.filter.CsrfCookieWebFilter;
import dh.bff.oauth2.handler.CustomLoginSuccessHandler;
import dh.bff.repository.OriginPreservingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.List;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final ReactiveClientRegistrationRepository clientRegistrationRepository;

    @Bean
    public SecurityWebFilterChain gatewaySecurityWebFilterChain(ServerHttpSecurity http) {

        CookieServerCsrfTokenRepository cookieServerCsrfTokenRepository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
        cookieServerCsrfTokenRepository.setCookiePath("/");
        cookieServerCsrfTokenRepository.setCookieCustomizer(cookie -> cookie
                .secure(false)
                .sameSite("Lax"));

        return http
                .cors(Customizer.withDefaults())
                .csrf(csrf -> csrf
                        .csrfTokenRepository(cookieServerCsrfTokenRepository)
                        .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler()))
                .addFilterAfter(new CsrfCookieWebFilter(cookieServerCsrfTokenRepository), SecurityWebFiltersOrder.CSRF)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/login/**", "/public/**", "/api/auth/sign-out").permitAll()
                        .anyExchange().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .authorizationRequestRepository(new OriginPreservingRepository())
                        .authenticationSuccessHandler(new CustomLoginSuccessHandler()))
                .requestCache(cache -> cache
                        .requestCache(new WebSessionServerRequestCache()))
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .build();
    }

    @Bean
    public UrlBasedCorsConfigurationSource corsWebFilter() {
        CorsConfiguration corsConfiguration = new CorsConfiguration();
        corsConfiguration.setAllowCredentials(true);
        corsConfiguration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
        corsConfiguration.setAllowedHeaders(List.of("*"));
        corsConfiguration.setAllowedOrigins(List.of(ClientInfo.getClientInfo(), "http://10.117.9.40:4000"));

        UrlBasedCorsConfigurationSource urlBasedCorsConfigurationSource = new UrlBasedCorsConfigurationSource();
        urlBasedCorsConfigurationSource.registerCorsConfiguration("/**", corsConfiguration);
        return urlBasedCorsConfigurationSource;
    }
}
