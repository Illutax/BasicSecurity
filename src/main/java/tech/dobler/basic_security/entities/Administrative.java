package tech.dobler.basic_security.entities;

public interface Administrative
{
	boolean isAdmin();

	boolean isEnabled();

	String getEmail();

	String getPassword();

}
