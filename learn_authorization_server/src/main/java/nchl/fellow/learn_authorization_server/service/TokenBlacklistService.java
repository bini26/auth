package nchl.fellow.learn_authorization_server.service;

import org.springframework.stereotype.Service;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class TokenBlacklistService {

    private final Set<String> blacklistedAccessToken  = ConcurrentHashMap.newKeySet();
    private final Set<String> blacklistedRefreshToken = ConcurrentHashMap.newKeySet();

    public void revokeAccessToken(String accessToken){
        blacklistedAccessToken.add(accessToken);
    }

    public void revokeRefreshToken(String refreshToken){
        blacklistedRefreshToken.add(refreshToken);
    }

    public boolean isAccessTokenRevoked(String token){
        return blacklistedAccessToken.contains(token);
    }

    public boolean isRefreshTokenRevoked(String token){
        return blacklistedRefreshToken.contains(token);
    }


}
