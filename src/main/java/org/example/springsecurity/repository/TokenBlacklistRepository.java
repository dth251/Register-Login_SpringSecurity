package org.example.springsecurity.repository;


import org.example.springsecurity.entity.TokenBlacklist;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.Instant;

@Repository
public interface TokenBlacklistRepository extends JpaRepository<TokenBlacklist, Long> {
    boolean existsByToken(String token);

    @Modifying
    @Query("DELETE FROM TokenBlacklist tb WHERE tb.expiredAt < :now")
    void deleteAllExpired(Instant now);
}
