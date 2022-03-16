package uz.base.sessioninmemory.security;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;
import uz.base.sessioninmemory.enities.Role;
import uz.base.sessioninmemory.enities.User;
import uz.base.sessioninmemory.servises.UserService;

import java.util.HashSet;
import java.util.Set;

@Component
public class LoginAuthenticationProvider implements AuthenticationProvider {

    private final UserService userService;

    public LoginAuthenticationProvider(UserService userService) {
        this.userService = userService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String username = authentication.getName();
        String password = (String) authentication.getCredentials();
        User retrievedUser = userService.login(username, password);
        Set<SimpleGrantedAuthority> authorities = setAuthorities(retrievedUser);
        return new UsernamePasswordAuthenticationToken(retrievedUser.getId(), password, authorities);
    }

    private Set<SimpleGrantedAuthority> setAuthorities(User retrievedUser) {
        Set<SimpleGrantedAuthority> authorities = new HashSet<>();
        for (Role role : retrievedUser.getRoles()) {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        }
        return authorities;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(UsernamePasswordAuthenticationToken.class);
    }
}