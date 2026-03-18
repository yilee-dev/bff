package dh.bff.oauth2.converter;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.*;
import java.util.stream.Collectors;

public class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        Object realmAccess = jwt.getClaim("realm_access");

        if (realmAccess instanceof Map<?, ?> map) {
            authorities.addAll(extractRoles(map));
        }

        Object resourceAccess = jwt.getClaim("resource_access");
        if (resourceAccess instanceof Map<?, ?> map) {
            Object clientAccess = map.get("api-gateway");
            if (clientAccess instanceof Map<?, ?> clientMap) {
                authorities.addAll(extractRoles(clientMap));
            }
        }

        return authorities;
    }

    private List<SimpleGrantedAuthority> extractRoles(Map<?, ?> map) {
        Object roles = map.get("roles");
        if (roles instanceof Collection<?> roleList) {
            return roleList.stream()
                    .filter(String.class::isInstance)
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();
        }
        return Collections.emptyList();
    }
}
