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
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.net.URI;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.security.oauth2.client.filter.ClientConfigurationTestUtil.*;

/**
 * Tests {@link AuthorizationRequestRedirectFilter}.
 *
 * @author Joe Grandja
 */
public class AuthorizationRequestRedirectFilterTests {

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenFilterProcessingBaseUriIsNullThenThrowIllegalArgumentException() {
		new AuthorizationRequestRedirectFilter(null, mock(ClientConfigurationRepository.class), mock(AuthorizationRequestUriBuilder.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenClientConfigurationRepositoryIsNullThenThrowIllegalArgumentException() {
		new AuthorizationRequestRedirectFilter(null, mock(AuthorizationRequestUriBuilder.class));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorWhenAuthorizationRequestUriBuilderIsNullThenThrowIllegalArgumentException() {
		new AuthorizationRequestRedirectFilter(mock(ClientConfigurationRepository.class), null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetWhenClientConfigurationsIsEmptyThenThrowIllegalArgumentException() {
		ClientConfigurationRepository clientConfigurationRepository = mock(ClientConfigurationRepository.class);
		when(clientConfigurationRepository.getConfigurations()).thenReturn(Collections.emptyList());
		AuthorizationRequestRedirectFilter filter = new AuthorizationRequestRedirectFilter(
				clientConfigurationRepository, mock(AuthorizationRequestUriBuilder.class));
		filter.afterPropertiesSet();
	}

	@Test
	public void doFilterWhenRequestDoesNotMatchClientThenContinueChain() throws Exception {
		ClientConfiguration clientConfiguration = googleClientConfiguration();
		String authorizationUri = clientConfiguration.getAuthorizeUri();
		AuthorizationRequestRedirectFilter filter =
				setupFilter(authorizationUri, clientConfiguration);

		String requestURI = "/path";
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestURI);
		request.setServletPath(requestURI);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verify(filterChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void doFilterWhenRequestMatchesClientThenRedirectForAuthorization() throws Exception {
		ClientConfiguration clientConfiguration = googleClientConfiguration();
		String authorizationUri = clientConfiguration.getAuthorizeUri();
		AuthorizationRequestRedirectFilter filter =
				setupFilter(authorizationUri, clientConfiguration);

		String requestUri = AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_BASE_URI +
				"/" + clientConfiguration.getClientAlias();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);        // Request should not proceed up the chain

		assertThat(response.getRedirectedUrl()).isEqualTo(authorizationUri);
	}

	@Test
	public void doFilterWhenRequestMatchesClientThenAuthorizationRequestSavedInSession() throws Exception {
		ClientConfiguration clientConfiguration = githubClientConfiguration();
		String authorizationUri = clientConfiguration.getAuthorizeUri();
		AuthorizationRequestRedirectFilter filter =
				setupFilter(authorizationUri, clientConfiguration);

		String requestUri = AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_BASE_URI +
				"/" + clientConfiguration.getClientAlias();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);        // Request should not proceed up the chain

		// The authorization request attributes are saved in the session before the redirect happens
		AuthorizationRequestAttributes authorizationRequestAttributes =
				(AuthorizationRequestAttributes) request.getSession().getAttribute(AuthorizationUtil.SAVED_AUTHORIZATION_REQUEST);
		assertThat(authorizationRequestAttributes).isNotNull();

		assertThat(authorizationRequestAttributes.getAuthorizeUri()).isNotNull();
		assertThat(authorizationRequestAttributes.getGrantType()).isNotNull();
		assertThat(authorizationRequestAttributes.getResponseType()).isNotNull();
		assertThat(authorizationRequestAttributes.getClientId()).isNotNull();
		assertThat(authorizationRequestAttributes.getRedirectUri()).isNotNull();
		assertThat(authorizationRequestAttributes.getScope()).isNotNull();
		assertThat(authorizationRequestAttributes.getState()).isNotNull();
	}

	@Test
	public void doFilterWhenCustomFilterProcessingBaseUriThenRequestStillMatchesClient() throws Exception {
		String filterProcessingBaseUri = "/oauth2-login";
		ClientConfiguration clientConfiguration = githubClientConfiguration();

		verifyRequestMatchesClientWithCustomFilterProcessingBaseUri(filterProcessingBaseUri, clientConfiguration);
	}

	@Test
	public void doFilterWhenCustomFilterProcessingBaseUriWithTrailingSlashThenRequestStillMatchesClient() throws Exception {
		String filterProcessingBaseUri = "/oauth2-login/";
		ClientConfiguration clientConfiguration = googleClientConfiguration();

		verifyRequestMatchesClientWithCustomFilterProcessingBaseUri(filterProcessingBaseUri, clientConfiguration);
	}

	@Test
	public void doFilterWhenCustomFilterProcessingBaseUriWithoutLeadingSlashThenRequestStillMatchesClient() throws Exception {
		String filterProcessingBaseUri = "oauth2-login";
		ClientConfiguration clientConfiguration = githubClientConfiguration();

		verifyRequestMatchesClientWithCustomFilterProcessingBaseUri(filterProcessingBaseUri, clientConfiguration);
	}

	@Test(expected = IllegalArgumentException.class)
	public void doFilterWhenAuthorizationRequestUriBuilderReturnsNullThenThrowIllegalArgumentException() throws Exception {
		ClientConfiguration clientConfiguration = githubClientConfiguration();

		AuthorizationRequestUriBuilder authorizationUriBuilder = mock(AuthorizationRequestUriBuilder.class);
		when(authorizationUriBuilder.build(any(AuthorizationRequestAttributes.class))).thenReturn(null);

		AuthorizationRequestRedirectFilter filter = setupFilter(authorizationUriBuilder, clientConfiguration);

		String requestUri = AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_BASE_URI +
				"/" + clientConfiguration.getClientAlias();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);
	}

	private void verifyRequestMatchesClientWithCustomFilterProcessingBaseUri(
			String filterProcessingBaseUri, ClientConfiguration clientConfiguration) throws Exception {

		String authorizationUri = clientConfiguration.getAuthorizeUri();
		AuthorizationRequestRedirectFilter filter =
				setupFilter(filterProcessingBaseUri, authorizationUri, clientConfiguration);

		String requestUri = filterProcessingBaseUri + "/" + clientConfiguration.getClientAlias();
		if (!requestUri.startsWith("/")) {
			requestUri = "/" + requestUri;
		}
		MockHttpServletRequest request = new MockHttpServletRequest("GET", requestUri);
		request.setServletPath(requestUri);
		MockHttpServletResponse response = new MockHttpServletResponse();
		FilterChain filterChain = mock(FilterChain.class);

		filter.doFilter(request, response, filterChain);

		verifyZeroInteractions(filterChain);        // Request should not proceed up the chain if matched
	}

	private AuthorizationRequestRedirectFilter setupFilter(
			String authorizationUri, ClientConfiguration... configurations) throws Exception {

		return setupFilter(AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_BASE_URI,
				authorizationUri, configurations);
	}

	private AuthorizationRequestRedirectFilter setupFilter(String filterProcessingBaseUri, String authorizationUri,
														   ClientConfiguration... configurations) throws Exception {

		AuthorizationRequestUriBuilder authorizationUriBuilder = mock(AuthorizationRequestUriBuilder.class);
		URI authorizationURI = new URI(authorizationUri);
		when(authorizationUriBuilder.build(any(AuthorizationRequestAttributes.class))).thenReturn(authorizationURI);

		return setupFilter(filterProcessingBaseUri, authorizationUriBuilder, configurations);
	}

	private AuthorizationRequestRedirectFilter setupFilter(AuthorizationRequestUriBuilder authorizationUriBuilder,
														   ClientConfiguration... configurations) throws Exception {

		return setupFilter(AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_BASE_URI,
				authorizationUriBuilder, configurations);
	}

	private AuthorizationRequestRedirectFilter setupFilter(String filterProcessingBaseUri,
														   AuthorizationRequestUriBuilder authorizationUriBuilder,
														   ClientConfiguration... configurations) throws Exception {

		ClientConfigurationRepository clientConfigurationRepository = clientConfigurationRepository(configurations);

		AuthorizationRequestRedirectFilter filter = new AuthorizationRequestRedirectFilter(
				filterProcessingBaseUri, clientConfigurationRepository, authorizationUriBuilder);
		filter.afterPropertiesSet();

		return filter;
	}
}