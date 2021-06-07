package io.opensaber.claim.repository;

import io.opensaber.claim.entity.Claim;
import io.opensaber.claim.entity.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ClaimRepository extends JpaRepository<Claim, String> {
    List<Claim> findByRoles(List<Role> roles);
}
