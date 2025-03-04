package nchl.fellow.learn_authorization_server.config;


import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;


import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Configuration
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityFilterChain asFilterChain(HttpSecurity http) throws Exception {

//        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http); deprecated
        //OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = new OAuth2AuthorizationServerConfigurer();
        //  authorizationServerConfigurer.oidc(Customizer.withDefaults());

//        http.apply(authorizationServerConfigurer);  marked as removal
        //    authorizationServerConfigurer.configure(http);

        //   http.exceptionHandling(e->e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));


        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer
                                .oidc(Customizer.withDefaults())    // Enable OpenID Connect 1.0
                )
                .authorizeHttpRequests((authorize) ->
                        authorize
                                .anyRequest().authenticated()
                )
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint("/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                );
        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterchain(HttpSecurity http) throws Exception {

        http.formLogin(Customizer.withDefaults());

        http.authorizeHttpRequests(c -> c.anyRequest().authenticated());


        return http.build();
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {

        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);

    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder().build();
    }

//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
//        return context -> {
//            JwtClaimsSet.Builder claims = context.getClaims();
//            claims.claim("priority", "HIGH");
//            Set<String> authorities = context.getPrincipal().getAuthorities()
//                    .stream()
//                    .map(grantedAuthority -> grantedAuthority.getAuthority())
//                    .collect(Collectors.toSet());
//
//            context.getClaims().claim("roles", authorities);
//        };

//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
//        return context -> {
//            // Extract roles and authorities from the user
//            Set<String> roles = context.getPrincipal().getAuthorities()
//                    .stream()
//                    .filter(grantedAuthority -> grantedAuthority.getAuthority().startsWith("ROLE_"))
//                    .map(grantedAuthority -> grantedAuthority.getAuthority())
//                    .collect(Collectors.toSet());
//
//            Set<String> authorities = context.getPrincipal().getAuthorities()
//                    .stream()
//                    .filter(grantedAuthority -> !grantedAuthority.getAuthority().startsWith("ROLE_"))
//                    .map(grantedAuthority -> grantedAuthority.getAuthority())
//                    .collect(Collectors.toSet());
//
//            // Add custom claims to the JWT
//            context.getClaims().claim("roles", roles); // Add roles
//            context.getClaims().claim("authorities", authorities); // Add authorities
//            context.getClaims().claim("priority", "HIGH"); // Add priority (example)
//        };


//    @Bean
//    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
//        return context -> {
//            // Extract roles and authorities from the user
//            Set<String> roles = context.getPrincipal().getAuthorities()
//                    .stream()
//                    .filter(grantedAuthority -> grantedAuthority.getAuthority().startsWith("ROLE_"))
//                    .map(grantedAuthority -> grantedAuthority.getAuthority())
//                    .collect(Collectors.toSet());
//
//            Set<String> authorities = context.getPrincipal().getAuthorities()
//                    .stream()
//                    .filter(grantedAuthority -> !grantedAuthority.getAuthority().startsWith("ROLE_"))
//                    .map(grantedAuthority -> grantedAuthority.getAuthority())
//                    .collect(Collectors.toSet());
//
//            // Add custom claims to the JWT
//            context.getClaims().claim("roles", roles); // Add roles
//            context.getClaims().claim("authorities", authorities); // Add authorities
//            context.getClaims().claim("priority", "HIGH"); // Add priority (example)
//        };
//    }


    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
        return context -> {

            Set<String> roles = context.getPrincipal().getAuthorities()
                    .stream()
                    .filter(grantedAuthority -> grantedAuthority.getAuthority().startsWith("ROLE_"))
                    .map(grantedAuthority -> grantedAuthority.getAuthority())
                    .collect(Collectors.toSet());

            Set<String> authorities = context.getPrincipal().getAuthorities()
                    .stream()
                    .filter(grantedAuthority -> !grantedAuthority.getAuthority().startsWith("ROLE_"))
                    .map(grantedAuthority -> grantedAuthority.getAuthority())
                    .collect(Collectors.toSet());

            context.getClaims().claim("roles", roles);
            context.getClaims().claim("authorities", authorities);
            context.getClaims().claim("priority", "HIGH");

            List<String> audience = determineAudienceforUser(context.getPrincipal());
            context.getClaims().audience(audience);

        };
    }

    private List<String> determineAudienceforUser(Authentication principle){
        if(principle.getAuthorities().contains(new SimpleGrantedAuthority("ROLE_ADMIN"))){
            return List.of("resource-server-1", "resource-server-2","resource-server-4","resource-server-3","resource-server-5");

        }
        else{
            return List.of("resource-server-1", "resource-server-2","resource-server-4");


        }
    }


}
