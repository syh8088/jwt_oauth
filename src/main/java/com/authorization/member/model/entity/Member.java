package com.authorization.member.model.entity;

import com.authorization.common.enums.OauthType;
import com.authorization.common.model.entity.Common;
import com.authorization.role.model.entity.Role;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter
public class Member extends Common {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long memberNo;

    private String id;

    private String password;

    private String name;

    @Enumerated(EnumType.STRING)
    private OauthType oauthType;

    private String oauthId;

    @ManyToMany(fetch = FetchType.EAGER)
    @JoinTable(name = "member_role_mapping", joinColumns = @JoinColumn(name = "memberNo"), inverseJoinColumns = @JoinColumn(name = "roleNo"))
    private List<Role> roles = new ArrayList<>();
}
