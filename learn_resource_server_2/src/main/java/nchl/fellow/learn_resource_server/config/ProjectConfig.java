package nchl.fellow.learn_resource_server.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class ProjectConfig {

    @Value("${introspectionUri}")
    private String introspectionUri;
    @Value("${resourceserver.clientID}")
    private String resourceServerClientID;
    @Value("${resourceserver.secret}")
    private String resourceServerSecret;


    @Value("${keySetURI}")
    private String keySetUri;


    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

        http.oauth2ResourceServer(
                c->c.jwt(j->j.jwkSetUri(keySetUri)
                        .jwtAuthenticationConverter(jwtAuthenticationConverter())));
        http.authorizeHttpRequests(
                c->c.anyRequest()
                                  .authenticated());

        return http.build();

    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();

        // Create a custom converter to map roles, authorities, and priority
        Converter<Jwt, Collection<GrantedAuthority>> customAuthoritiesConverter = jwt -> {
            Collection<GrantedAuthority> grantedAuthorities = new ArrayList<>();

            // Extract roles
            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null) {
                grantedAuthorities.addAll(
                        roles.stream()
                                .map(role -> new SimpleGrantedAuthority(role))
                                .collect(Collectors.toList())
                );
            }

            // Extract authorities
            List<String> authorities = jwt.getClaimAsStringList("authorities");
            if (authorities != null) {
                grantedAuthorities.addAll(
                        authorities.stream()
                                .map(authority -> new SimpleGrantedAuthority(authority))
                                .collect(Collectors.toList())
                );
            }

            // Extract priority (optional, if needed as an authority)
            String priority = jwt.getClaimAsString("priority");
            if (priority != null) {
                grantedAuthorities.add(new SimpleGrantedAuthority("PRIORITY_" + priority));
            }

            List<String> audience = jwt.getAudience();
            if(audience == null || !audience.contains("resource-server-2")){
                throw new IllegalArgumentException("InvalidAudience");
            }

            return grantedAuthorities;
        };

        // Set the custom converter
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(customAuthoritiesConverter);

        return jwtAuthenticationConverter;
    }
}
