/*
 * Copyright 2012-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.filter;

import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.core.OAuth2Attributes;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.client.filter.ClientConfigurationTestUtil.*;

/**
 * Tests {@link AuthorizationCodeGrantProcessingFilter}.
 *
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantProcessingFilterTests {

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetWhenClientConfigurationRepositoryIsNullThenThrowIllegalArgumentException() {
		AuthorizationCodeGrantProcessingFilter filter = new AuthorizationCodeGrantProcessingFilter();
		filter.setAuthenticationManager(mock(AuthenticationManager.class));
		filter.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetWhenAuthenticationManagerIsNullThenThrowIllegalArgumentException() {
		AuthorizationCodeGrantProcessingFilter filter = new AuthorizationCodeGrantProcessingFilter();
		filter.setClientConfigurationRepository(mock(ClientConfigurationRepository.class));
		filter.afterPropertiesSet();
	}

	@Test
	public void doFilterWhenNotAuthorizationCodeGrantResponseThenContinueChain() throws Exception {
		ClientConfiguration clientConfiguration = googleClientConfiguration();

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientConfiguration));

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		verify(filter, never()).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenAuthorizationCodeGrantErrorResponseThenAuthenticationFailureHandlerIsCalled() throws Exception {
		ClientConfiguration clientConfiguration = githubClientConfiguration();

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientConfiguration));
		AuthenticationFailureHandler failureHandler = mock(AuthenticationFailureHandler.class);
		filter.setAuthenticationFailureHandler(failureHandler);

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String errorCode = "some error code";
		request.addParameter(OAuth2Attributes.ERROR, errorCode);
		request.addParameter(OAuth2Attributes.STATE, "some state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filter).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));

		ArgumentCaptor<AuthenticationException> authenticationExceptionArgCaptor =
				ArgumentCaptor.forClass(AuthenticationException.class);
		verify(failureHandler).onAuthenticationFailure(any(HttpServletRequest.class), any(HttpServletResponse.class),
				authenticationExceptionArgCaptor.capture());
		assertThat(authenticationExceptionArgCaptor.getValue()).isInstanceOf(AuthenticationServiceException.class);
		assertThat(authenticationExceptionArgCaptor.getValue().getMessage()).isEqualTo("Authorization error: " + errorCode);
	}

	@Test
	public void doFilterWhenAuthorizationCodeGrantSuccessResponseThenAuthenticationSuccessHandlerIsCalled() throws Exception {
		ClientConfiguration clientConfiguration = githubClientConfiguration();

		TestingAuthenticationToken authentication = new TestingAuthenticationToken("joe", "password", "user", "admin");
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);
		when(authenticationManager.authenticate(any(Authentication.class))).thenReturn(authentication);

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(authenticationManager, clientConfiguration));
		AuthenticationSuccessHandler successHandler = mock(AuthenticationSuccessHandler.class);
		filter.setAuthenticationSuccessHandler(successHandler);

		String requestURI = "/path";
		clientConfiguration.setRedirectUri(requestURI);		// requestUri must be same as client redirectUri to pass validation
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String authCode = "some code";
		String state = "some state";
		request.addParameter(OAuth2Attributes.CODE, authCode);
		request.addParameter(OAuth2Attributes.STATE, state);
		setupAuthorizationRequest(request, clientConfiguration, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filter).attemptAuthentication(any(HttpServletRequest.class), any(HttpServletResponse.class));

		ArgumentCaptor<Authentication> authenticationArgCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(successHandler).onAuthenticationSuccess(any(HttpServletRequest.class), any(HttpServletResponse.class),
				authenticationArgCaptor.capture());
		assertThat(authenticationArgCaptor.getValue()).isEqualTo(authentication);
	}

	@Test(expected = OAuth2Exception.class)
	public void doFilterWhenAuthorizationCodeGrantSuccessResponseAndNoMatchingAuthorizationRequestThenThrowOAuth2Exception() throws Exception {
		ClientConfiguration clientConfiguration = githubClientConfiguration();

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientConfiguration));

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String authCode = "some code";
		String state = "some state";
		request.addParameter(OAuth2Attributes.CODE, authCode);
		request.addParameter(OAuth2Attributes.STATE, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);
	}

	@Test(expected = OAuth2Exception.class)
	public void doFilterWhenAuthorizationCodeGrantSuccessResponseWithInvalidStateParamThenThrowOAuth2Exception() throws Exception {
		ClientConfiguration clientConfiguration = githubClientConfiguration();

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientConfiguration));

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String authCode = "some code";
		String state = "some other state";
		request.addParameter(OAuth2Attributes.CODE, authCode);
		request.addParameter(OAuth2Attributes.STATE, state);
		setupAuthorizationRequest(request, clientConfiguration, "some state");
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);
	}

	@Test(expected = OAuth2Exception.class)
	public void doFilterWhenAuthorizationCodeGrantSuccessResponseWithInvalidRedirectUriParamThenThrowOAuth2Exception() throws Exception {
		ClientConfiguration clientConfiguration = githubClientConfiguration();

		AuthorizationCodeGrantProcessingFilter filter = spy(setupFilter(clientConfiguration));

		String requestURI = "/path2";
		clientConfiguration.setRedirectUri("/path");
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		String authCode = "some code";
		String state = "some state";
		request.addParameter(OAuth2Attributes.CODE, authCode);
		request.addParameter(OAuth2Attributes.STATE, state);
		setupAuthorizationRequest(request, clientConfiguration, state);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);
	}

	private AuthorizationCodeGrantProcessingFilter setupFilter(ClientConfiguration... configurations) throws Exception {
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class);

		return setupFilter(authenticationManager, configurations);
	}

	private AuthorizationCodeGrantProcessingFilter setupFilter(
			AuthenticationManager authenticationManager, ClientConfiguration... configurations) throws Exception {

		ClientConfigurationRepository clientConfigurationRepository = clientConfigurationRepository(configurations);

		AuthorizationCodeGrantProcessingFilter filter = new AuthorizationCodeGrantProcessingFilter();
		filter.setClientConfigurationRepository(clientConfigurationRepository);
		filter.setAuthenticationManager(authenticationManager);
		filter.afterPropertiesSet();

		return filter;
	}

	private void setupAuthorizationRequest(HttpServletRequest request, ClientConfiguration configuration, String state) {
		AuthorizationRequestAttributes authorizationRequestAttributes =
				AuthorizationRequestAttributes.authorizationCodeGrant(
						configuration.getAuthorizeUri(),
						configuration.getClientId(),
						configuration.getRedirectUri(),
						configuration.getScope(),
						state);

		request.getSession().setAttribute(AuthorizationUtil.SAVED_AUTHORIZATION_REQUEST, authorizationRequestAttributes);
	}
}