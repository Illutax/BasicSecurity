package tech.dobler.basic_security.repository;

import java.util.Optional;

public interface Fetchable<U>
{
	Optional<U> findByEmail(String email);
}
