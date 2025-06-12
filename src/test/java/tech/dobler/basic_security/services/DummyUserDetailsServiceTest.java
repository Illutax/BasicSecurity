package tech.dobler.basic_security.services;

import org.assertj.core.description.Description;
import org.assertj.core.description.TextDescription;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCrypt;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class DummyUserDetailsServiceTest {

    private final DummyUserDetailsService userDetailsService = new DummyUserDetailsService(new DummyUserDetailsService.DummyRepository());

    @Test
    @DisplayName("Should load user by username successfully")
    void shouldLoadUserByUsernameSuccessfully() {

        // Act
        UserDetails result = userDetailsService.loadUserByUsername("a@b.c");

        // Assert
        assertThat(result).isNotNull();
        assertThat(result.getUsername()).isEqualTo("a@b.c");
        assertThat(BCrypt.checkpw("d", "{bcrypt}$2a$10$hJ09/qw2bFzmLcxalIG09uvx5ytFjrstYgrJhjlRp6XNNJPFeivz6"))
                .as(new TextDescription("Password %s should match hash %s", "d", result.getPassword()))
                .isTrue();
    }

    @Test
    @DisplayName("Should throw exception for null username")
    void shouldThrowExceptionForNullUsername() {
        // Act & Assert
        assertThatThrownBy(() -> userDetailsService.loadUserByUsername(null))
                .isInstanceOf(IllegalArgumentException.class);
    }

}
