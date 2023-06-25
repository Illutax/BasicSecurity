package tech.dobler.basic_security.dvs;

import java.io.Serializable;

public interface ID<T> extends Serializable
{
	T getId();
}
