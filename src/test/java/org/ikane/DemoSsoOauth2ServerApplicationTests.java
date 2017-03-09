package org.ikane;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

@RunWith(SpringJUnit4ClassRunner.class)
@SpringBootTest(classes = DemoSsoOauth2ServerApplication.class)
@WebAppConfiguration
public class DemoSsoOauth2ServerApplicationTests {

	@Test
	public void contextLoads() {
	}

}
