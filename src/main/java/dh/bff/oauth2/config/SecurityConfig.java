package dh.bff.oauth2.config;

import dh.bff.constant.ClientInfo;
import dh.bff.oauth2.filter.CsrfCookieWebFilter;
import dh.bff.oauth2.handler.CustomLoginSuccessHandler;
import dh.bff.oauth2.manager.DynamicAuthorizationManager;
import dh.bff.repository.OriginPreservingRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveRedisTemplate;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.UrlBasedCorsConfigurationSource;

import java.util.*;
import java.util.stream.Collectors;

@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final DynamicAuthorizationManager dynamicAuthorizationManager;

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
                        .pathMatchers("/api/auth/me").permitAll()
                        .pathMatchers("/api/admin/auth/update").hasRole("RENTALS_MANAGER")
                        .anyExchange().access(dynamicAuthorizationManager))
                .oauth2Login(oauth2 -> oauth2
                        .authorizationRequestRepository(new OriginPreservingRepository())
                        .authenticationSuccessHandler(new CustomLoginSuccessHandler()))
                .requestCache(cache -> cache
                        .requestCache(new WebSessionServerRequestCache()))
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .build();
    }

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                mappedAuthorities.add(authority);

                if (authority instanceof OidcUserAuthority oidcAuth) {
                    Map<String, Object> claims = oidcAuth.getIdToken().getClaims();

                    extractRoles(claims.get("realm_access"), mappedAuthorities);

                    if (claims.get("resource_access") instanceof Map<?, ?> resourceAccess) {
                        resourceAccess.values().forEach(clientAccess ->
                                extractRoles(clientAccess, mappedAuthorities)
                        );
                    }
                }
            });

            return mappedAuthorities;
        };
    }

    private void extractRoles(Object accessObj, Set<GrantedAuthority> mappedAuthorities) {
        if (accessObj instanceof Map<?, ?> accessMap) {
            Object rolesObj = accessMap.get("roles");
            if (rolesObj instanceof Collection<?> roles) {
                roles.forEach(role -> {
                    String roleName = "ROLE_" + role.toString();
                    mappedAuthorities.add(new SimpleGrantedAuthority(roleName));
                });
            }
        }
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
