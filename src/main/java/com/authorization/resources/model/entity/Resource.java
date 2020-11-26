package com.authorization.resources.model.entity;

import com.authorization.common.model.entity.Common;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;

@Entity
@Getter
@Setter
@ToString
@Table(name = "resources")
public class Resource extends Common {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private long resourceNo;
    private String resourceName;
    private Long orderNum;
    private String resourceType;
}
