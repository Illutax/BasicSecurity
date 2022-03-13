package tech.dobler.basic_security.dvs;


public enum UserRole {
	ADMIN("ADMIN"), USER("USER");

	private final String role;

	UserRole(String role) {
		this.role = role;
	}

	public static UserRole of(String role) {
		for (UserRole r :
				UserRole.values()) {
			if (r.role.equalsIgnoreCase(role)) return r;
		}
		return null;
	}

	@Override public String toString() {
		return role;
	}
}
