package tech.dobler.basic_security.configurations;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import tech.dobler.basic_security.dvs.UserRole;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;

@Configuration
@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter
{
	private static final String[] PUBLIC_URLS = new String[] {
			"/login",
			"/login**",
			"/register",
	};
	private final UserDetailsService userDetailsService;
	private String[] additionalPublicUrls = new String[0];
	private String defaultSuccessUrl = "/";
	@Value("${security.enable-csrf:false}")
	private boolean enableCsrf;

	public WebSecurityConfiguration(UserDetailsService userDetailsService)
	{
		this.userDetailsService = userDetailsService;
	}

	public void setAdditionalPublicUrls(final String... additionalPublicUrls)
	{
		this.additionalPublicUrls = additionalPublicUrls;
	}

	public void setDefaultSuccessUrl(final String url)
	{
		this.defaultSuccessUrl = url;
	}

	@Bean
	public DaoAuthenticationProvider authProvider(final PasswordEncoder passwordEncoder)
	{
		DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
		authProvider.setUserDetailsService(userDetailsService);
		authProvider.setPasswordEncoder(passwordEncoder);
		return authProvider;
	}

	@Override
	protected void configure(final HttpSecurity http) throws Exception
	{
		// @formatter:off
		http
				.authorizeRequests()
					.antMatchers("/admin").hasAuthority(UserRole.ADMIN.name())
					.antMatchers(getPublicUrls()).permitAll()
					.anyRequest()
					.authenticated()
				.and()
				.formLogin()
					.loginPage("/login")
					.defaultSuccessUrl(defaultSuccessUrl)
					.failureHandler(redirectingAuthenticationFailureHandler())
					.permitAll()
				.and()
				.logout()
					.logoutSuccessUrl("/login?logout")
					.logoutUrl("/logout")
					.logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET"))
					.invalidateHttpSession(true)
					.deleteCookies("JSESSIONID")
					.permitAll();
		// @formatter:on

		if (enableCsrf)
		{
			http.csrf();
		}
		else
		{
			http.csrf().disable();
		}
	}

	private String[] getPublicUrls()
	{
		final var length = additionalPublicUrls.length;
		final var allPublicUrls = Arrays.copyOf(PUBLIC_URLS, PUBLIC_URLS.length + length);
		System.arraycopy(additionalPublicUrls, 0, allPublicUrls, PUBLIC_URLS.length, length);
		return allPublicUrls;
	}

	private AuthenticationFailureHandler redirectingAuthenticationFailureHandler()
	{
		return new SimpleUrlAuthenticationFailureHandler()
		{
			@Override
			public void onAuthenticationFailure(final HttpServletRequest request, final HttpServletResponse response,
					final AuthenticationException exception) throws ServletException, IOException
			{
				final var redirectParam = exception.getCause() instanceof LockedException
						? "locked"
						: "error";
				super.setDefaultFailureUrl("/login?" + redirectParam);
				super.onAuthenticationFailure(request, response, exception);
			}
		};
	}

	@Bean
	public PasswordEncoder passwordEncoder()
	{
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

}