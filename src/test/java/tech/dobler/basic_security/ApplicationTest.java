package tech.dobler.basic_security;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.web.context.WebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT,
		classes = { BasicSecurityApplication.class })
class ApplicationTest
{
	@LocalServerPort
	protected int port;

	@Autowired
	private WebApplicationContext context;

	@Test
	void contextLoads()
	{
		assertThat(context).isNotNull();
	}

}
