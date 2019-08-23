package com.authorization.member.repository;

import com.authorization.member.model.entity.Member;
import org.springframework.data.jpa.repository.JpaRepository;

public interface MemberRepository extends JpaRepository<Member, Long> {
    Member findByIdAndUseYn(String id, boolean useYn);
}
