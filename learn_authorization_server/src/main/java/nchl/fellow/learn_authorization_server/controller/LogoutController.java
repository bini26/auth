package nchl.fellow.learn_authorization_server.controller;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import nchl.fellow.learn_authorization_server.service.TokenBlacklistService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
public class LogoutController {

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @PostMapping("/logout")
    public ResponseEntity<?> logout(HttpServletRequest request, HttpServletResponse response,
                                    Authentication authentication, @RequestBody Map<String, String>tokenRequest){

        new SecurityContextLogoutHandler().logout(request, response, authentication);

        String accessToken = tokenRequest.get("access_token");
        if(accessToken != null){
            tokenBlacklistService.revokeAccessToken(accessToken);
        }

        String refreshToken = tokenRequest.get("refresh_token");
        if(refreshToken != null){
            tokenBlacklistService.revokeRefreshToken(refreshToken);
        }

        return ResponseEntity.ok().build();

    }
}
