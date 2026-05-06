package dh.bff.oauth2.config;

import dh.bff.oauth2.converter.KeycloakRoleConverter;
import dh.bff.oauth2.filter.CsrfCookieWebFilter;
import dh.bff.oauth2.handler.CustomLoginSuccessHandler;
import dh.bff.oauth2.manager.DynamicAuthorizationManager;
import dh.bff.repository.OriginPreservingRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.WebSessionServerSecurityContextRepository;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.csrf.ServerCsrfTokenRequestAttributeHandler;
import org.springframework.security.web.server.savedrequest.WebSessionServerRequestCache;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.reactive.CorsConfigurationSource;
import org.springframework.web.server.ServerWebExchange;

import java.util.*;
import java.util.regex.Pattern;

@Slf4j
@Configuration
@EnableWebFluxSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final DynamicAuthorizationManager dynamicAuthorizationManager;

    @Value("${app.cors.allowed-origins}")
    private String allowedOrigins;

    /** 사내 IP 대역 패턴 — 10.x.x.x, 172.16~31.x.x, 192.168.x.x + localhost */
    private static final Pattern INTERNAL_ORIGIN = Pattern.compile(
            "^https?://(" +
                    "10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}" +
                    "|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}" +
                    "|192\\.168\\.\\d{1,3}\\.\\d{1,3}" +
                    "|localhost" +
                    ")(:\\d+)?$"
    );

    @Bean
    public SecurityWebFilterChain gatewaySecurityWebFilterChain(ServerHttpSecurity http) {

        CookieServerCsrfTokenRepository cookieServerCsrfTokenRepository = CookieServerCsrfTokenRepository.withHttpOnlyFalse();
        cookieServerCsrfTokenRepository.setCookiePath("/");
        cookieServerCsrfTokenRepository.setCookieCustomizer(cookie -> cookie
                .secure(false)
                .sameSite("Lax"));

        return http
                .securityContextRepository(new WebSessionServerSecurityContextRepository())
                .cors(cors -> cors.configurationSource(corsConfigurationSource()))
                .csrf(csrf -> csrf
                        .csrfTokenRepository(cookieServerCsrfTokenRepository)
                        .csrfTokenRequestHandler(new ServerCsrfTokenRequestAttributeHandler())
                        .requireCsrfProtectionMatcher(exchange -> {
                            String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                            if (auth != null && auth.startsWith("Bearer "))
                                return ServerWebExchangeMatcher.MatchResult.notMatch();

                            String method = exchange.getRequest().getMethod().name();
                            if (Set.of("GET", "HEAD", "TRACE", "OPTIONS").contains(method))
                                return ServerWebExchangeMatcher.MatchResult.notMatch();

                            MediaType contentType = exchange.getRequest().getHeaders().getContentType();
                            if (contentType != null && contentType.isCompatibleWith(MediaType.MULTIPART_FORM_DATA))
                                return ServerWebExchangeMatcher.MatchResult.notMatch();
                            return ServerWebExchangeMatcher.MatchResult.match();
                        }))
                .addFilterAfter(new CsrfCookieWebFilter(cookieServerCsrfTokenRepository), SecurityWebFiltersOrder.CSRF)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/login/**", "/public/**", "/api/auth/sign-out").permitAll()
                        .pathMatchers("/api/auth/me").permitAll()
                        .pathMatchers("/bff/users", "/bff/users/**").authenticated()
                        .pathMatchers("/bff/departments", "/bff/departments/**").authenticated()
                        .pathMatchers("/api/admin/**").hasRole("RENTAL_MANAGER")
                        .pathMatchers("/api/**").access(dynamicAuthorizationManager)
                        .anyExchange().authenticated())
                .oauth2Login(oauth2 -> oauth2
                        .authorizationRequestRepository(new OriginPreservingRepository())
                        .authenticationSuccessHandler(new CustomLoginSuccessHandler()))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(bearerTokenConverter())))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((exchange, e) -> {
                            String auth = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
                            if (auth != null && auth.startsWith("Bearer ")) {
                                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
                                return exchange.getResponse().setComplete();
                            }
                            // 브라우저 요청은 기존대로 Keycloak 리다이렉트
                            return new org.springframework.security.web.server.authentication.RedirectServerAuthenticationEntryPoint("/oauth2/authorization/keycloak")
                                    .commence(exchange, e);
                        }))
                .requestCache(cache -> cache
                        .requestCache(new WebSessionServerRequestCache()))
                .logout(ServerHttpSecurity.LogoutSpec::disable)
                .build();
    }

    @Bean
    public ReactiveJwtAuthenticationConverterAdapter bearerTokenConverter() {
        var delegate = new org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter();
        delegate.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
        return new ReactiveJwtAuthenticationConverterAdapter(delegate);
    }

    @Bean
    public GrantedAuthoritiesMapper userAuthoritiesMapper() {
        return (authorities) -> {
            Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

            authorities.forEach(authority -> {
                mappedAuthorities.add(authority);

                if (authority instanceof OidcUserAuthority oidcAuth) {
                    Map<String, Object> claims = oidcAuth.getIdToken().getClaims();

                    // realm roles → ROLE_ 접두사
                    extractRolesWithPrefix(claims.get("realm_access"), "ROLE_", mappedAuthorities);

                    // api-gateway client roles → 접두사 없음 (backend PermissionsConverter와 일치)
                    if (claims.get("resource_access") instanceof Map<?, ?> resourceAccess) {
                        Object clientAccess = resourceAccess.get("api-gateway");
                        extractRolesWithPrefix(clientAccess, "", mappedAuthorities);
                    }
                }
            });

            return mappedAuthorities;
        };
    }

    private void extractRolesWithPrefix(Object accessObj, String prefix, Set<GrantedAuthority> mappedAuthorities) {
        if (accessObj instanceof Map<?, ?> accessMap) {
            Object rolesObj = accessMap.get("roles");
            if (rolesObj instanceof Collection<?> roles) {
                roles.forEach(role -> mappedAuthorities.add(new SimpleGrantedAuthority(prefix + role)));
            }
        }
    }

    /**
     * 동적 CORS 설정 — 요청 Origin이 사내 IP 대역이면 자동 허용.
     * app.cors.allowed-origins에 명시된 origin은 항상 허용됩니다.
     */
    private CorsConfigurationSource corsConfigurationSource() {
        Set<String> explicitOrigins = new HashSet<>(List.of(allowedOrigins.split(",")));

        return (ServerWebExchange exchange) -> {
            CorsConfiguration config = new CorsConfiguration();
            config.setAllowCredentials(true);
            config.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "OPTIONS"));
            config.setAllowedHeaders(List.of("*"));
            config.setMaxAge(3600L);

            String origin = exchange.getRequest().getHeaders().getOrigin();
            if (origin != null && (explicitOrigins.contains(origin) || INTERNAL_ORIGIN.matcher(origin).matches())) {
                config.setAllowedOrigins(List.of(origin));
            } else {
                config.setAllowedOrigins(List.copyOf(explicitOrigins));
            }

            return config;
        };
    }
}
