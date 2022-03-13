package tech.dobler.basic_security.entities;

import lombok.EqualsAndHashCode;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

@EqualsAndHashCode(callSuper = true)
public class AppUserDetails<T> extends org.springframework.security.core.userdetails.User
{
	private final transient T user;

	public AppUserDetails(final T user,
			final String email,
			final String encryptedPassword,
			final Collection<? extends GrantedAuthority> authorities)
	{
		super(email, encryptedPassword, authorities);
		this.user = user;
	}

	public T getLoggedInUser()
	{
		return user;
	}

}
