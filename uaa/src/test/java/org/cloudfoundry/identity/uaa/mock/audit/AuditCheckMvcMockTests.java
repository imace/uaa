package org.cloudfoundry.identity.uaa.mock.audit;

import org.cloudfoundry.identity.uaa.audit.AuditEvent;
import org.cloudfoundry.identity.uaa.audit.LoggingAuditService;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.event.BadCredentialsListener;
import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.oauth.event.ClientAdminEventPublisher;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import static org.mockito.Mockito.mock;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class AuditCheckMvcMockTests {

    private XmlWebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient = null;
    private UaaTestAccounts testAccounts = null;
    private ApplicationEventPublisher applicationEventPublisher = null;
    private ArgumentCaptor<AuditEvent> captor = null;
    private BadCredentialsListener badCredentialsListener;
    private LoggingAuditService loggingAuditService;

    @Before
    public void setUp() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean(FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain).build();

        testClient = new TestClient(mockMvc);
        testAccounts = UaaTestAccounts.standard(null);

        loggingAuditService = webApplicationContext.getBean(LoggingAuditService.class);
        captor = ArgumentCaptor.forClass(AuditEvent.class);

    }

    @Test
    public void userLoginTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", testAccounts.getPassword());
        ResultActions result = mockMvc.perform(loginPost);
        //success means a 302 to / (failure is 302 to /login?error...)
        result.andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location","/"));


    }
}
