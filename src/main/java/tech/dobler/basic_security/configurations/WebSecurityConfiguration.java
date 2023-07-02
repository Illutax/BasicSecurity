package tech.dobler.basic_security.configurations;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import tech.dobler.basic_security.dvs.UserRole;

import java.io.IOException;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration {
    private static final String[] PUBLIC_URLS = new String[]{
            "/login",
            "/login**",
            "/register",
    };
    private final UserDetailsService userDetailsService;
    private String[] additionalPublicUrls = new String[0];
    private String defaultSuccessUrl = "/";
    private String defaultAccessDeniedPage = "/";

    @Value("${security.enable-csrf:false}")
    private boolean enableCsrf;
    private String[] publicUrls;
    public WebSecurityConfiguration(UserDetailsService userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    public void setDefaultAccessDeniedPage(String defaultAccessDeniedPage) {
        this.defaultAccessDeniedPage = defaultAccessDeniedPage;
    }

    public void setAdditionalPublicUrls(final String... additionalPublicUrls) {
        this.additionalPublicUrls = additionalPublicUrls;
    }

    public void setDefaultSuccessUrl(final String url) {
        this.defaultSuccessUrl = url;
    }

    @Bean
    public DaoAuthenticationProvider authProvider(final PasswordEncoder passwordEncoder) {
        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
        authProvider.setUserDetailsService(userDetailsService);
        authProvider.setPasswordEncoder(passwordEncoder);
        return authProvider;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth
                        .requestMatchers("/admin/**").hasAuthority(UserRole.ADMIN.name())
                        .requestMatchers(getPublicUrls()).permitAll()
                        .anyRequest().authenticated())
                .exceptionHandling(exceptionHandling ->
                        exceptionHandling.accessDeniedPage(defaultAccessDeniedPage))
                .formLogin(customizer -> customizer
                        .loginPage("/login")
                        .defaultSuccessUrl(defaultSuccessUrl)
                        .failureHandler(redirectingAuthenticationFailureHandler())
                        .permitAll())
                .logout(customizer -> customizer
                        .logoutSuccessUrl("/login?logout")
                        .logoutUrl("/logout")
                        .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll());

        if (!enableCsrf) {
            http.csrf(AbstractHttpConfigurer::disable);
        }
        return http.build();
    }

    private String[] getPublicUrls() {
        if (publicUrls == null) {
            final var length = additionalPublicUrls.length;
            publicUrls = Arrays.copyOf(PUBLIC_URLS, PUBLIC_URLS.length + length);
            System.arraycopy(additionalPublicUrls, 0, publicUrls, PUBLIC_URLS.length, length);
        }
        return publicUrls;
    }

    private AuthenticationFailureHandler redirectingAuthenticationFailureHandler() {
        return new SimpleUrlAuthenticationFailureHandler() {
            @Override
            public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
                                                final AuthenticationException exception) throws ServletException, IOException {
                final var redirectParam = exception.getCause() instanceof LockedException
                        ? "locked"
                        : "error";
                super.setDefaultFailureUrl("/login?" + redirectParam);
                super.onAuthenticationFailure(request, response, exception);
            }
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

}
