package com.authorization.common.config.handler;

import com.authorization.member.model.entity.Member;
import com.authorization.member.repository.MemberRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.time.LocalDateTime;

public class OAuthSuccessHandler implements AuthenticationSuccessHandler {

    private final MemberRepository memberRepository;

    public OAuthSuccessHandler(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        String userId = userDetails.getUsername();
        request.getSession().setAttribute("userId", userId);

        Member member = memberRepository.findByIdAndUseYn(userId, true);
        member.setTodayLogin(LocalDateTime.now());

    }

}
