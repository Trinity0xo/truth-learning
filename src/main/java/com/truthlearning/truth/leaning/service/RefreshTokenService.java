package com.truthlearning.truth.leaning.service;

import com.truthlearning.truth.leaning.domain.RefreshToken;
import com.truthlearning.truth.leaning.domain.User;
import com.truthlearning.truth.leaning.repository.RefreshTokenRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.HashMap;

@Service
public class RefreshTokenService {
    private final RefreshTokenRepository refreshTokenRepository;

    public RefreshTokenService(RefreshTokenRepository refreshTokenRepository){
        this.refreshTokenRepository = refreshTokenRepository;
    }

    public void handleAddRefreshTokenToUser(User user, String token, Instant iat, Instant exp){
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setUser(user);
        refreshToken.setTokenValue(token);
        refreshToken.setIat(iat);
        refreshToken.setExp(exp);

        this.refreshTokenRepository.save(refreshToken);
    }

    public RefreshToken handleGetRefreshToken(User user, String token){
        return this.refreshTokenRepository.findByUserAndTokenValue(user, token).orElse(null);
    }

    public boolean handleCheckValidExpireTime(RefreshToken refreshToken, Instant iat, Instant exp){
        boolean isValid = true;

        if (!exp.equals(refreshToken.getExp()) || !iat.equals(refreshToken.getIat())) {
            isValid = false;
        }

        if(Instant.now().isAfter(refreshToken.getExp())){
            isValid = false;
        }

        return isValid;
    }

    public void handleDeleteOldRefreshToken(RefreshToken refreshToken){
        this.refreshTokenRepository.delete(refreshToken);
    }

}
