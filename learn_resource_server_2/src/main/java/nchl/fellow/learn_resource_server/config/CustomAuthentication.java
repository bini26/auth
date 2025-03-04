package nchl.fellow.learn_resource_server.config;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Collection;

public class CustomAuthentication extends JwtAuthenticationToken {

    private final String priority;

   // private final String roles;

    public CustomAuthentication(Jwt jwt,Collection<? extends GrantedAuthority > authorities, String priority, String roles){

        super(jwt, authorities);
        this.priority = priority;
//        /this.roles = roles;
    }
    public CustomAuthentication(Jwt jwt,Collection<? extends GrantedAuthority > authorities, String priority){

        super(jwt, authorities);
        this.priority = priority;
    }

    public String getPriority(){
        return priority;
    }

//    public String getRoles(){
//        return roles;
//    }

}
