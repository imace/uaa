/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.mock.audit;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.contains;
import static org.mockito.Matchers.matches;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.audit.AuditEventType;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.audit.event.ApprovalModifiedEvent;
import org.cloudfoundry.identity.uaa.audit.event.TokenIssuedEvent;
import org.cloudfoundry.identity.uaa.audit.event.UserModifiedEvent;
import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.ClientAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.PrincipalAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.oauth.approval.Approval;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeEvent;
import org.cloudfoundry.identity.uaa.password.event.PasswordChangeFailureEvent;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.endpoints.PasswordResetEndpoints;
import org.cloudfoundry.identity.uaa.test.DefaultIntegrationTestConfig;
import org.cloudfoundry.identity.uaa.test.IntegrationTestContextLoader;
import org.cloudfoundry.identity.uaa.test.TestApplicationEventListener;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.codehaus.jackson.map.ObjectMapper;
import org.hamcrest.Matcher;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import com.googlecode.flyway.core.Flyway;
import junit.framework.Assert;

@RunWith(SpringJUnit4ClassRunner.class)
@WebAppConfiguration
@ContextConfiguration(classes = DefaultIntegrationTestConfig.class, loader = IntegrationTestContextLoader.class)
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
public class AuditCheckMvcMockTests {

    @Autowired
    AnnotationConfigWebApplicationContext webApplicationContext;

    @Autowired
    FilterChainProxy filterChainProxy;

    @Autowired
    Flyway flyway;

    @Autowired
    ClientRegistrationService clientRegistrationService;

    private ApplicationListener<AbstractUaaEvent> listener;
    private MockMvc mockMvc;
    private TestClient testClient;
    private UaaTestAccounts testAccounts;
    private TestApplicationEventListener<AbstractUaaEvent> testListener;

    @Before
    public void setUp() throws Exception {
        listener = mock(new DefaultApplicationListener<AbstractUaaEvent>() {}.getClass());
        webApplicationContext.addApplicationListener(listener);
        testListener = TestApplicationEventListener.forEventClass(AbstractUaaEvent.class);
        webApplicationContext.addApplicationListener(testListener);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(filterChainProxy)
                .build();

        testClient = new TestClient(mockMvc);
        testAccounts = UaaTestAccounts.standard(null);
    }

    @After
    public void tearDown() throws Exception{
        flyway.clean();
    }

    @Test
    public void userLoginTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", testAccounts.getPassword());

        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor  = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(listener).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(testAccounts.getUserName(), event.getUser().getUsername());
    }

    @Test
    public void userLoginAuthenticateEndpointTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", testAccounts.getPassword());

        mockMvc.perform(loginPost)
            .andExpect(status().isOk())
            .andExpect(content().string("{\"username\":\""+testAccounts.getUserName()+"\"}"));

        ArgumentCaptor<UserAuthenticationSuccessEvent> captor  = ArgumentCaptor.forClass(UserAuthenticationSuccessEvent.class);
        verify(listener).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = captor.getValue();
        assertEquals(testAccounts.getUserName(), event.getUser().getUsername());
    }


    @Test
    public void invalidPasswordLoginFailedTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", "");
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/login?error=true"));

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(2)).onApplicationEvent(captor.capture());

        UserAuthenticationFailureEvent event1 = (UserAuthenticationFailureEvent)captor.getAllValues().get(0);
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent)captor.getAllValues().get(1);
        assertEquals(testAccounts.getUserName(), event1.getUser().getUsername());
        assertEquals(testAccounts.getUserName(), event2.getName());
    }

    @Test
    public void invalidPasswordLoginAuthenticateEndpointTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/authenticate")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", "");
        mockMvc.perform(loginPost)
            .andExpect(status().isUnauthorized())
            .andExpect(content().string("{\"error\":\"authentication failed\"}"));

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(2)).onApplicationEvent(captor.capture());

        UserAuthenticationFailureEvent event1 = (UserAuthenticationFailureEvent)captor.getAllValues().get(0);
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent)captor.getAllValues().get(1);
        assertEquals(testAccounts.getUserName(), event1.getUser().getUsername());
        assertEquals(testAccounts.getUserName(), event2.getName());
    }

    @Test
    public void userNotFoundLoginFailedTest() throws Exception {
        String username = "test1234";

        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.TEXT_HTML_VALUE)
            .param("username", username)
            .param("password", testAccounts.getPassword());
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/login?error=true"));

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        UserNotFoundEvent event1 = (UserNotFoundEvent)captor.getAllValues().get(0);
        PrincipalAuthenticationFailureEvent event2 = (PrincipalAuthenticationFailureEvent)captor.getAllValues().get(1);
        assertEquals(username, ((Authentication)event1.getSource()).getName());
        assertEquals(username, event2.getName());
    }

    @Test
    public void userChangePasswordTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", testAccounts.getPassword());
        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));
        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = (UserAuthenticationSuccessEvent)captor.getValue();
        String userid = event.getUser().getId();

        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testAccounts.getUserName(), testAccounts.getPassword(), "password.write");
        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(4)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof TokenIssuedEvent);

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/"+userid+"/password")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + marissaToken)
            .content("{\n" +
                    "  \"password\": \"koala2\",\n" +
                    "  \"oldPassword\": \"" + testAccounts.getPassword() + "\"\n" +
                    "}");

        mockMvc.perform(changePasswordPut)
                .andExpect(status().isOk());

        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(5)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof PasswordChangeEvent);
        PasswordChangeEvent pw = (PasswordChangeEvent)captor.getValue();
        assertEquals(testAccounts.getUserName(), pw.getUser().getUsername());
        assertEquals("Password changed", pw.getMessage());
    }

    @Test
    public void userChangeInvalidPasswordTest() throws Exception {
        MockHttpServletRequestBuilder loginPost = post("/login.do")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .param("username", testAccounts.getUserName())
            .param("password", testAccounts.getPassword());

        //success means a 302 to / (failure is 302 to /login?error...)
        mockMvc.perform(loginPost)
                .andExpect(status().is3xxRedirection())
                .andExpect(header().string("Location", "/"));

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(1)).onApplicationEvent(captor.capture());
        UserAuthenticationSuccessEvent event = (UserAuthenticationSuccessEvent)captor.getValue();
        String userid = event.getUser().getId();

        String marissaToken = testClient.getUserOAuthAccessToken("app", "appclientsecret", testAccounts.getUserName(), testAccounts.getPassword(), "password.write");
        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(4)).onApplicationEvent(captor.capture());
        assertTrue(captor.getValue() instanceof TokenIssuedEvent);

        MockHttpServletRequestBuilder changePasswordPut = put("/Users/"+userid+"/password")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + marissaToken)
            .content("{\n" +
                    "  \"password\": \"koala2\",\n" +
                    "  \"oldPassword\": \"invalid\"\n" +
                    "}");

        mockMvc.perform(changePasswordPut)
                .andExpect(status().isUnauthorized());

        captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(5)).onApplicationEvent(captor.capture());

        assertTrue(captor.getValue() instanceof PasswordChangeFailureEvent);
        PasswordChangeFailureEvent pwfe = (PasswordChangeFailureEvent)captor.getValue();
        assertEquals(testAccounts.getUserName(), pwfe.getUser().getUsername());
        assertEquals("Old password is incorrect", pwfe.getMessage());
    }

    @Test
    public void loginServerPasswordChange() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");

        PasswordResetEndpoints.PasswordChange pwch = new PasswordResetEndpoints.PasswordChange();
        pwch.setUsername(testAccounts.getUserName());
        pwch.setCurrentPassword(testAccounts.getPassword());
        pwch.setNewPassword("koala2");

        MockHttpServletRequestBuilder changePasswordPost = post("/password_change")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(new ObjectMapper().writeValueAsBytes(pwch));

        mockMvc.perform(changePasswordPost)
                .andExpect(status().isOk());

        ArgumentCaptor<AbstractUaaEvent> captor  = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(3)).onApplicationEvent(captor.capture());
        PasswordChangeEvent pce = (PasswordChangeEvent)captor.getValue();
        assertEquals(testAccounts.getUserName(), pce.getUser().getUsername());
        assertEquals("Password changed", pce.getMessage());
    }

    @Test
    public void loginServerInvalidPasswordChange() throws Exception {
        String loginToken = testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");

        PasswordResetEndpoints.PasswordChange pwch = new PasswordResetEndpoints.PasswordChange();
        pwch.setUsername(testAccounts.getUserName());
        pwch.setCurrentPassword("dsadasda");
        pwch.setNewPassword("koala2");

        MockHttpServletRequestBuilder changePasswordPost = post("/password_change")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + loginToken)
            .content(new ObjectMapper().writeValueAsBytes(pwch));

        mockMvc.perform(changePasswordPost)
            .andExpect(status().isUnauthorized());

        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, times(3)).onApplicationEvent(captor.capture());
        PasswordChangeFailureEvent pce = (PasswordChangeFailureEvent) captor.getValue();
        assertEquals(testAccounts.getUserName(), pce.getUser().getUsername());
        assertEquals("Old password is incorrect", pce.getMessage());
    }

    @Test
    public void clientAuthenticationSuccess() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        testClient.getClientCredentialsOAuthAccessToken("login", "loginsecret", "oauth.login");
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        ClientAuthenticationSuccessEvent event = (ClientAuthenticationSuccessEvent)captor.getAllValues().get(0);
        assertEquals("login", event.getClientId());
    }

    @Test
    public void clientAuthenticationFailure() throws Exception {
        ArgumentCaptor<AbstractUaaEvent> captor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        String basicDigestHeaderValue = "Basic "
            + new String(Base64.encodeBase64(("login:loginsecretwrong").getBytes()));
        MockHttpServletRequestBuilder oauthTokenPost = post("/oauth/token")
            .header("Authorization", basicDigestHeaderValue)
            .param("grant_type", "client_credentials")
            .param("client_id", "login")
            .param("scope", "oauth.login");
        mockMvc.perform(oauthTokenPost).andExpect(status().isUnauthorized());
        verify(listener, times(2)).onApplicationEvent(captor.capture());
        ClientAuthenticationFailureEvent event = (ClientAuthenticationFailureEvent)captor.getValue();
        assertEquals("login", event.getClientId());
    }

    @Test
    public void testUserApprovalAdded() throws Exception {
        clientRegistrationService.updateClientDetails(new BaseClientDetails("login", "oauth", "oauth.approvals", "password", "oauth.login"));

        String marissaToken = testClient.getUserOAuthAccessToken("login", "loginsecret", testAccounts.getUserName(), testAccounts.getPassword(), "oauth.approvals");

        Approval[] approvals = {new Approval(testAccounts.getUserName(), "app", "cloud_controller.read", 1000, Approval.ApprovalStatus.APPROVED)};

        MockHttpServletRequestBuilder approvalsPut = put("/approvals")
                .accept(MediaType.APPLICATION_JSON_VALUE)
                .contentType(MediaType.APPLICATION_JSON)
                .header("Authorization", "Bearer " + marissaToken)
                .content(new ObjectMapper().writeValueAsBytes(approvals));

        testListener.clearEvents();

        mockMvc.perform(approvalsPut)
                .andExpect(status().isOk());

        Assert.assertEquals(1, testListener.getEventCount());

        ApprovalModifiedEvent approvalModifiedEvent = (ApprovalModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals("marissa", approvalModifiedEvent.getAuthentication().getName());
    }

    @Test
    public void testUserCreatedEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write");

        String username = "jacob", firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(new ObjectMapper().writeValueAsBytes(user));

        testListener.clearEvents();

        mockMvc.perform(userPost)
            .andExpect(status().isCreated());

        Assert.assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        Assert.assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserCreatedEvent, userModifiedEvent.getAuditEvent().getType());

    }

    @Test
    public void testUserModifiedEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write");

        String username = "jacob", firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        String modifiedFirstName = firstName+lastName;
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(new ObjectMapper().writeValueAsBytes(user));

        ResultActions result = mockMvc.perform(userPost)
            .andExpect(status().isCreated());

        user = new ObjectMapper().readValue(result.andReturn().getResponse().getContentAsByteArray(), ScimUser.class);
        testListener.clearEvents();

        user.setName(new ScimUser.Name(modifiedFirstName, lastName));
        MockHttpServletRequestBuilder userPut = put("/Users/"+user.getId())
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", user.getVersion())
            .content(new ObjectMapper().writeValueAsBytes(user));

        mockMvc.perform(userPut).andExpect(status().isOk());

        Assert.assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        Assert.assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserModifiedEvent, userModifiedEvent.getAuditEvent().getType());
    }

    @Test
    public void testUserVerifiedEvent() throws Exception {
        String adminToken = testClient.getClientCredentialsOAuthAccessToken(
            testAccounts.getAdminClientId(),
            testAccounts.getAdminClientSecret(),
            "uaa.admin,scim.write");

        String username = "jacob", firstName = "Jacob", lastName = "Gyllenhammar", email = "jacob@gyllenhammar.non";
        String modifiedFirstName = firstName+lastName;
        ScimUser user = new ScimUser();
        user.setUserName(username);
        user.setName(new ScimUser.Name(firstName, lastName));
        user.addEmail(email);

        MockHttpServletRequestBuilder userPost = post("/Users")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .contentType(MediaType.APPLICATION_JSON)
            .header("Authorization", "Bearer " + adminToken)
            .content(new ObjectMapper().writeValueAsBytes(user));

        ResultActions result = mockMvc.perform(userPost)
            .andExpect(status().isCreated());
        user = new ObjectMapper().readValue(result.andReturn().getResponse().getContentAsByteArray(), ScimUser.class);

        testListener.clearEvents();

        MockHttpServletRequestBuilder verifyGet = get("/Users/" + user.getId() + "/verify")
            .accept(MediaType.APPLICATION_JSON_VALUE)
            .header("Authorization", "Bearer " + adminToken)
            .header("If-Match", user.getVersion());

        mockMvc.perform(verifyGet).andDo(print());//.andExpect(status().isOk());

        Assert.assertEquals(1, testListener.getEventCount());

        UserModifiedEvent userModifiedEvent = (UserModifiedEvent) testListener.getLatestEvent();
        Assert.assertEquals(testAccounts.getAdminClientId(), userModifiedEvent.getAuthentication().getName());
        Assert.assertEquals(username, userModifiedEvent.getUsername());
        assertEquals(AuditEventType.UserVerifiedEvent, userModifiedEvent.getAuditEvent().getType());
    }



    private class DefaultApplicationListener<T extends ApplicationEvent> implements ApplicationListener<T> {
        @Override
        public void onApplicationEvent(T event) {
        }
    }
}
