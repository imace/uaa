package org.cloudfoundry.identity.uaa.mock.audit;

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationListener;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class AuditCheckMvcMockTests {

    private XmlWebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private UaaTestAccounts testAccounts = null;
    private ApplicationListener<AbstractUaaEvent> listener = null;
    private TestClient testClient;

    @Before
    public void setUp() throws Exception {
        ApplicationListener<AbstractUaaEvent> ab = new ApplicationListener<AbstractUaaEvent>() {
            @Override
            public void onApplicationEvent(AbstractUaaEvent abstractUaaEvent) {
            }
        };

        listener = mock(ab.getClass());

        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setServletContext(new MockServletContext());
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.addApplicationListener(listener);
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean(FilterChainProxy.class);

        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain).build();
        testClient = new TestClient(mockMvc);
        testAccounts = UaaTestAccounts.standard(null);

    }

    @Test
    public void userLoginTest() throws Exception {
        ArgumentCaptor<UserAuthenticationSuccessEvent> captor  = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", testAccounts.getPassword());
        ResultActions result = mockMvc.perform(loginPost);
        //success means a 302 to / (failure is 302 to /login?error...)
        result.andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location","/"));

        verify(listener).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(testAccounts.getUserName(), event.getUser().getUsername());
    }

    @Test
    public void invalidPasswordLoginFailedTest() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", "");
        ResultActions result = mockMvc.perform(loginPost);
        //success means a 302 to / (failure is 302 to /login?error...)
        result.andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location","/login?error=true"));

        verify(listener, times(2)).onApplicationEvent(captor.capture());
        UserAuthenticationFailureEvent event1 = (UserAuthenticationFailureEvent)captor.getAllValues().get(0);
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent)captor.getAllValues().get(1);
        assertEquals(testAccounts.getUserName(), event1.getUser().getUsername());
        assertEquals(testAccounts.getUserName(), event2.getName());
    }

    @Test
    public void userNotFoundLoginFailedTest() throws Exception {
        String username = "test1234";
        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", username)
            .param("password", testAccounts.getPassword());
        ResultActions result = mockMvc.perform(loginPost);
        //success means a 302 to / (failure is 302 to /login?error...)
        result.andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location","/login?error=true"));

        verify(listener, times(2)).onApplicationEvent(captor.capture());
        UserNotFoundEvent event1 = (UserNotFoundEvent)captor.getAllValues().get(0);
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent)captor.getAllValues().get(1);
        assertEquals(username, ((Authentication)event1.getSource()).getName());
        assertEquals(username, event2.getName());
    }

    @Test
    public void userChangePasswordTest() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", testAccounts.getPassword());
        ResultActions result = mockMvc.perform(loginPost);
        //success means a 302 to / (failure is 302 to /login?error...)
        result.andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location","/"));
        verify(listener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = (UserAuthenticationSuccessEvent)captor.getValue();
        String userid = event.getUser().getId();
        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);

        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testAccounts.getUserName(), testAccounts.getPassword(), "password.write");
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/"+userid+"/password")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + marissaToken)
            .content("{\n" +
                "  \"password\": \"koala2\",\n" +
                "  \"oldPassword\": \""+testAccounts.getPassword()+"\"\n" +
                "}");

        result = mockMvc.perform(changePasswordPut);
        result.andExpect(status().isOk());
        verify(listener, times(3)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof PasswordChangeEvent);
        PasswordChangeEvent pw = (PasswordChangeEvent)captor.getValue();
        assertEquals(testAccounts.getUserName(), pw.getUser().getUsername());
        assertEquals("Password changed", pw.getMessage());
    }

    @Test
    public void userChangeInvalidPasswordTest() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", testAccounts.getPassword());
        ResultActions result = mockMvc.perform(loginPost);
        //success means a 302 to / (failure is 302 to /login?error...)
        result.andExpect(status().is3xxRedirection())
            .andExpect(header().string("Location","/"));
        verify(listener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = (UserAuthenticationSuccessEvent)captor.getValue();
        String userid = event.getUser().getId();
        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);

        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testAccounts.getUserName(), testAccounts.getPassword(), "password.write");
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/"+userid+"/password")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + marissaToken)
            .content("{\n" +
                "  \"password\": \"koala2\",\n" +
                "  \"oldPassword\": \"invalid\"\n" +
                "}");

        result = mockMvc.perform(changePasswordPut);
        result.andExpect(status().isUnauthorized());
        verify(listener, times(3)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof PasswordChangeFailureEvent);
        PasswordChangeFailureEvent pw = (PasswordChangeFailureEvent)captor.getValue();
        assertEquals(testAccounts.getUserName(), pw.getUser().getUsername());
        assertEquals("Old password is incorrect", pw.getMessage());
    }




}
