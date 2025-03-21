package com.truthlearning.truth.leaning.service;

import com.truthlearning.truth.leaning.domain.User;
import com.truthlearning.truth.leaning.domain.VerifyToken;
import com.truthlearning.truth.leaning.repository.VerifyTokenRepository;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.UUID;

@Service
public class VerifyTokenService {
    private final VerifyTokenRepository verifyTokenRepository;

    public VerifyTokenService(VerifyTokenRepository verifyTokenRepository) {
        this.verifyTokenRepository = verifyTokenRepository;
    }

    public VerifyToken handleCreateVerifyToken(User user, long expireTime){
        Instant now = Instant.now();
        Instant validity = now.plus(expireTime, ChronoUnit.SECONDS);

        String token = UUID.randomUUID().toString();

        VerifyToken verifyToken = new VerifyToken();
        verifyToken.setUser(user);
        verifyToken.setTokenValue(token);
        verifyToken.setExpireTime(validity);

        return this.verifyTokenRepository.save(verifyToken);
    }

    public VerifyToken handleGetVerifyEmailTokenByTokenValue(String tokenValue){
        return this.verifyTokenRepository.findByTokenValue(tokenValue).orElse(null);
    }

    public VerifyToken handleGetVerifyEmailTokenByUser(User user){
        return this.verifyTokenRepository.findByUser(user).orElse(null);
    }


    public boolean handleCheckValidExpireTime(VerifyToken verifyToken){
        boolean isValid = true;

        if(Instant.now().isAfter(verifyToken.getExpireTime())){
            isValid = false;
        }

        return isValid;
    }

    public void handleDeleteVerifyEmailToken(VerifyToken verifyToken){
        this.verifyTokenRepository.delete(verifyToken);
    }
}
