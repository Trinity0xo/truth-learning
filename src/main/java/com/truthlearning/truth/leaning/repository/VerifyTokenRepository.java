package com.truthlearning.truth.leaning.repository;

import com.truthlearning.truth.leaning.domain.User;
import com.truthlearning.truth.leaning.domain.VerifyToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface VerifyTokenRepository extends JpaRepository<VerifyToken, Long> {
    Optional<VerifyToken> findByTokenValue(String tokenValue);
    Optional<VerifyToken> findByUser(User user);
}
