package tech.dobler.basic_security.services;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Repository;
import org.springframework.stereotype.Service;
import tech.dobler.basic_security.entities.Administrative;
import tech.dobler.basic_security.repository.Fetchable;

import java.util.Optional;

@Service
class DummyUserDetailsService extends AbstractAppUserDetailsService<DummyUserDetailsService.DummyUser, DummyUserDetailsService.DummyRepository>
{
	protected DummyUserDetailsService(final DummyRepository repository)
	{
		super(repository);
	}

	protected interface DummyUser extends Administrative
	{

	}

	@Repository
	static class DummyRepository implements Fetchable<DummyUser>
	{

		private static final PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		private final DummyUser concreteDummyUser = new DummyUser()
		{
			@Override
			public boolean isAdmin()
			{
				return true;
			}

			@Override
			public boolean isEnabled() {
				return true;
			}

			@Override
			public String getEmail()
			{
				return "a@b.c";
			}

			@Override
			public String getPassword()
			{
				return encoder.encode("d"); // NOSONAR this is just a dummy
			}
		};

		@Override
		public Optional<DummyUser> findByEmail(final String email)
		{
			return Optional.of(concreteDummyUser);
		}

	}

}
