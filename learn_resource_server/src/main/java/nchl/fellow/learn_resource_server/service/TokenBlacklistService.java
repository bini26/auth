package nchl.fellow.learn_resource_server.service;

import org.springframework.stereotype.Service;

import java.util.HashSet;
import java.util.Set;

@Service
public class TokenBlacklistService {

    private final Set<String> blacklistedTokens = new HashSet<>();

    public void revokeAccessToken(String token) {
        blacklistedTokens.add(token);
    }

    public boolean isAccessTokenRevoked(String token) {
        return blacklistedTokens.contains(token);
    }
}