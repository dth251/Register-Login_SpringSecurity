package org.example.springsecurity.entity;


import jakarta.persistence.*;
import lombok.*;

@Entity
@Table(name = "roles")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class Role {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    /**
     * Tên role, lưu dạng "ROLE_USER", "ROLE_ADMIN".
     * Prefix "ROLE_" là quy ước bắt buộc của Spring Security.
     */
    @Enumerated(EnumType.STRING)
    @Column(nullable = false, unique = true, length = 30)
    private ERole name;
}

