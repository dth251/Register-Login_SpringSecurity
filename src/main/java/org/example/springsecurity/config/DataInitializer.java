package org.example.springsecurity.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.example.springsecurity.entity.ERole;
import org.example.springsecurity.entity.Role;
import org.example.springsecurity.entity.User;
import org.example.springsecurity.repository.RoleRepository;
import org.example.springsecurity.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.Set;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    @Transactional
    public void run(String... args) {
        // 1. Seed bảng roles trước (nếu chưa có)
        Role roleUser  = seedRole(ERole.ROLE_USER);
        Role roleAdmin = seedRole(ERole.ROLE_ADMIN);

        // 2. Tạo tài khoản ADMIN mặc định (có cả ROLE_ADMIN lẫn ROLE_USER)
        if (!userRepository.existsByUsername("admin")) {
            User admin = User.builder()
                    .username("admin")
                    .email("admin@example.com")
                    .password(passwordEncoder.encode("admin123"))
                    .roles(Set.of(roleUser, roleAdmin))
                    .build();
            userRepository.save(admin);
            log.info("✅ Tạo tài khoản ADMIN mặc định: admin / admin123  [roles: ROLE_USER, ROLE_ADMIN]");
        }

        // 3. Tạo tài khoản USER mẫu (chỉ ROLE_USER)
        if (!userRepository.existsByUsername("user")) {
            User user = User.builder()
                    .username("user")
                    .email("user@example.com")
                    .password(passwordEncoder.encode("user123"))
                    .roles(Set.of(roleUser))
                    .build();
            userRepository.save(user);
            log.info("✅ Tạo tài khoản USER mẫu: user / user123  [roles: ROLE_USER]");
        }
    }

    /**
     * Tạo role nếu chưa tồn tại trong bảng roles, trả về entity đã được persist.
     */
    private Role seedRole(ERole erole) {
        return roleRepository.findByName(erole).orElseGet(() -> {
            Role r = Role.builder().name(erole).build();
            roleRepository.save(r);
            log.info("✅ Seed role: {}", erole);
            return r;
        });
    }
}

