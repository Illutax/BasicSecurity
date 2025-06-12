package tech.dobler.basic_security.services;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.util.Assert;
import tech.dobler.basic_security.exceptions.UserDeactivatedException;
import tech.dobler.basic_security.dvs.UserRole;
import tech.dobler.basic_security.entities.Administrative;
import tech.dobler.basic_security.entities.AppUserDetails;
import tech.dobler.basic_security.repository.Fetchable;

import java.util.ArrayList;
import java.util.List;

@Slf4j
public abstract class AbstractAppUserDetailsService<U extends Administrative, R extends Fetchable<U>> implements UserDetailsService
{
	protected final R repository;

	protected AbstractAppUserDetailsService(final R repository)
	{
		this.repository = repository;
	}

	public void authenticate(String userEmail)
	{
		UserDetails userDetails = loadUserByUsername(userEmail);
		Authentication auth = new UsernamePasswordAuthenticationToken(userDetails.getUsername(),
				userDetails.getPassword(),
				userDetails.getAuthorities());
		SecurityContextHolder.getContext().setAuthentication(auth);
		log.info("{} was authenticated", userEmail);
	}

	protected List<SimpleGrantedAuthority> createAuthorities(U user)
	{
		List<UserRole> authorities = new ArrayList<>();
		if (user.isAdmin())
		{
			authorities.add(UserRole.ADMIN);
		}
		authorities.add(UserRole.USER);

		return authorities.stream()
				.map(UserRole::name)
				.map(SimpleGrantedAuthority::new)
				.toList();
	}

	public AppUserDetails<U> getAuthenticationPrincipal()
	{
		//noinspection unchecked
		return (AppUserDetails<U>) SecurityContextHolder.getContext()
				.getAuthentication()
				.getPrincipal();
	}

	@Override
	public UserDetails loadUserByUsername(final String userEmail) throws UsernameNotFoundException
	{
		Assert.notNull(userEmail, "userEmail must not be null");
		U user = repository.findByEmail(userEmail)
				.orElseThrow(() -> {
					log.warn("Tried to login with {} and failed because it doesn't exist", userEmail);
					return new UsernameNotFoundException("Not Found");
				});

		if (!user.isEnabled()) {
			log.warn("Tried to login with {} and failed because it's deactivated", userEmail);
			throw new UserDeactivatedException("User %s was deactivated".formatted(userEmail));
		}
		AbstractAppUserDetailsService.log.info("Logging in with email: {}", userEmail);

		return new AppUserDetails<>(user, user.getEmail(), user.getPassword(), createAuthorities(user));
	}

}
