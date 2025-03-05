package nchl.fellow.learn_authorization_server.config;


import nchl.fellow.learn_authorization_server.service.TokenBlacklistService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.*;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.UUID;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class ProjectConfig {

    @Value("@{introspectionUrl}")
    private String introsectionUrl;
     @Value("@{resourceserver.clientId}")
    private String resourceServerClientId;
     @Value("@{resourceserver.secret}")
    private String resourceServerClientSecret;

     @Autowired
    private TokenBlacklistService tokenBlacklistService;
    @Bean
    public UserDetailsService uds(){
         var uds = new InMemoryUserDetailsManager();

         uds.createUser(User.withUsername("user").password("password").authorities("Read","ROLE_USER").build());
        uds.createUser(User.withUsername("user1").password("password").authorities("Read","ROLE_USER","WRITE").build());
        uds.createUser(User.withUsername("user2").password("password").authorities("Read","ROLE_USER","EDIT").build());
        uds.createUser(User.withUsername("admin1").password("password").authorities("Read","ROLE_ADMIN","WRITE","EDIT","DELETE").build());

        var admin = User.withUsername("admin")
                .password("password")
                .authorities("Read", "Write","ROLE_ADMIN")
                .build();
        uds.createUser(admin);
        return uds;


    }

    @Bean
    public PasswordEncoder passwordEncoder(){
        return  NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {

        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
              // .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                //.scope("CUSTOM")
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)//grant type for refresh token
                .scope(OidcScopes.OPENID)
                .scope("read")
                .scope("write")
                .redirectUri("https://www.manning.com/authorized")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofMinutes(5))// access token expires in 5minute
                        .refreshTokenTimeToLive(Duration.ofHours(24))//referesh token is expires in 24hrs
                        .build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

//    @Bean
//    public OAuth2TokenGenerator<?> tokenGenerator() {
//        return new OAuth2TokenGenerator<>() {
//            @Override
//            public OAuth2Token generate(OAuth2TokenContext context) {
//                OAuth2TokenType tokenType = context.getTokenType();
//                if (OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
//                    return generateAccessToken(context);
//                } else if (OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
//                    return generateRefreshToken(context);
//                }
//                throw new UnsupportedOperationException("Unsupported token type: " + tokenType.getValue());
//            }
//
//            private OAuth2AccessToken generateAccessToken(OAuth2TokenContext context) {
//                String tokenValue = generateSecureTokenValue();
//                return new OAuth2AccessToken(
//                        OAuth2AccessToken.TokenType.BEARER,
//                        tokenValue,
//                        context.getRegisteredClient().getClientIdIssuedAt(),
//                        context.getRegisteredClient().getClientSecretExpiresAt() // Use the expiration time from the context
//                );
//            }
//
//            private OAuth2RefreshToken generateRefreshToken(OAuth2TokenContext context) {
//                if (tokenBlacklistService.isAccessTokenRevoked(context.getAuthorizationGrant().getCredentials().toString())) {
//                    throw new IllegalArgumentException("Refresh token revoked");
//                }
//                String tokenValue = generateSecureTokenValue();
//                return new OAuth2RefreshToken(
//                        tokenValue,
//                        context.getRegisteredClient().getClientIdIssuedAt(),
//                        context.getRegisteredClient().getClientSecretExpiresAt() // Use the expiration time from the context
//                );
//            }
//
//            private String generateSecureTokenValue() {
//                return UUID.randomUUID().toString();
//            }
//        };
//    }

}

//
//
//
//
//
//        /*
//        *  //.authorizationGrantType(
//                //AuthorizationGrantType.AUTHORIZATION_CODE)
////                .authorizationGrantType(
////                AuthorizationGrantType.CLIENT_CREDENTIALS)
////               .clientAuthenticationMethod(
//               //ClientAuthenticationMethod.CLIENT_SECRET_BASIC)   // this is for opaque token rather then non-opaque token
//              //.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//              //.tokenSettings(TokenSettings.builder()
//               //.accessTokenFormat(OAuth2TokenFormat.REFERENCE) #A
//              //.build())   // this is for opaque token rather then non-opaque token
//                        //.authorizationGrantType(
//                //AuthorizationGrantType.REFRESH_TOKEN)     client can use any grant type
//                .redirectUri("https://www.manning.com/authorized")
//                .scope(OidcScopes.OPENID)
////                .scope("CUSTOM")
////                .clientSettings(ClientSettings.builder()
////                        .requireProofKey(false).build())//disable PKCE
//                .build();*/
//
//        return new InMemoryRegisteredClientRepository(registeredClient);
//    }
//    @Bean
//    public RegisteredClientRepository registeredClientRepository(){
//
//        RegisteredClient registeredClient =
//        RegisteredClient.withId(UUID.randomUUID().toString())
//                .clientId("client")
//                .clientSecret("secret")
//                .clientAuthenticationMethod(
//                        ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
//                .tokenSettings(TokenSettings.builder()
//                        .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
//                        .accessTokenTimeToLive(Duration.ofHours(12))
//                        .build())
//                .scope("CUSTOM")
//                .build();
//
//
//        RegisteredClient resourceServer =
//                RegisteredClient.withId(UUID.randomUUID().toString())
//                        .clientId("resource_server")
//                        .clientSecret("resource_server_secret")
//                        .clientAuthenticationMethod(
//                                ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//                        .authorizationGrantType(
//                                AuthorizationGrantType.CLIENT_CREDENTIALS)
//                        .build();
//
//        return new InMemoryRegisteredClientRepository( registeredClient,resourceServer);
//    }
//}


