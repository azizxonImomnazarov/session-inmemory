package uz.base.sessioninmemory.configs;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import uz.base.sessioninmemory.security.LoginAuthenticationProvider;
import uz.base.sessioninmemory.security.LoginSuccessHandler;

import static uz.base.sessioninmemory.constants.ApplicationConstants.*;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final LoginAuthenticationProvider loginAuthenticationProvider;

    private final LoginSuccessHandler loginSuccessHandler;

    public SecurityConfig(LoginAuthenticationProvider loginAuthenticationProvider, LoginSuccessHandler loginSuccessHandler) {
        this.loginAuthenticationProvider = loginAuthenticationProvider;
        this.loginSuccessHandler = loginSuccessHandler;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .authorizeRequests()
                // make sure to grant access to any login page you are forwarding to
                .antMatchers(LOGIN_URI).permitAll()
                .antMatchers("/admin/**").hasAuthority(ADMIN_ROLE)
                .antMatchers("/user/**").hasAuthority(USER_ROLE)
                .and()
                .authenticationProvider(loginAuthenticationProvider)
                .formLogin().loginPage(LOGIN_URI).successHandler(loginSuccessHandler)
                .and()
                .logout().logoutUrl(LOGOUT_URI).logoutSuccessUrl(LOGIN_URI).deleteCookies(JSESSIONID)
                .and()
                .sessionManagement()
                .maximumSessions(1)
                .expiredUrl(LOGIN_URI)
                .maxSessionsPreventsLogin(false)
                .and()
                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                .invalidSessionUrl(LOGIN_URI);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
        web.ignoring().antMatchers("/resources/**", "/static/**", "/css/**", "/js/**", "/images/**");
    }

}
