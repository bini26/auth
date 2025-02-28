package nchl.fellow.learn_resource_server.converter;

import nchl.fellow.learn_resource_server.config.CustomAuthentication;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class CustomJwtAuthenticationConverter implements Converter<Jwt, CustomAuthentication> {


    @Override
    public CustomAuthentication convert(Jwt source) {
        List<GrantedAuthority> authorities = List.of(() -> "read");
        String priority = String.valueOf(source.getClaims().get("priority"));
//        String roles = String.valueOf(source.getClaims().get("roles"));
      //  return new CustomAuthentication(source, authorities, priority,roles);
        return new CustomAuthentication(source, authorities, priority);
    }
}