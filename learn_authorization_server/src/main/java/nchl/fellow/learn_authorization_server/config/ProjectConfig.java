package nchl.fellow.learn_authorization_server.config;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import java.time.Duration;
import java.util.UUID;

@Configuration
@EnableMethodSecurity(prePostEnabled = true)
public class ProjectConfig {

    @Value("@{introspectionUrl}")
    private String introspectionUrl;
     @Value("@{resourceserver.clientId}")
    private String resourceServerClientId;
     @Value("@{resourceserver.secret}")
    private String resourceServerClientSecret;

    @Bean
    public UserDetailsService uds(){
         var uds = new InMemoryUserDetailsManager();

         uds.createUser(User.withUsername("user").password("password").authorities("Read").roles("USER").build());
        var admin = User.withUsername("admin")
                .password("password")
                .authorities("Read", "Write") // Add authorities
                .roles("ADMIN") // Add roles (automatically prefixed with "ROLE_")
                .build();
        uds.createUser(admin);
        System.out.println("Admin Authorities: " + admin.getAuthorities()); // Log authorities

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
                .scope(OidcScopes.OPENID)
                .redirectUri("https://www.manning.com/authorized")
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }}

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


