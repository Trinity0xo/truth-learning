package com.truthlearning.truth.leaning.repository;

import com.truthlearning.truth.leaning.domain.RefreshToken;
import com.truthlearning.truth.leaning.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByUserAndTokenValue(User user, String tokenValue);
}
