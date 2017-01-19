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
package org.springframework.security.oauth2.client.config.annotation.web.configurers;

import org.springframework.context.ApplicationContext;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.ui.DefaultOAuth2LoginPageGeneratingFilter;
import org.springframework.security.oauth2.client.filter.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.util.Assert;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Map;
import java.util.stream.Collectors;

import static org.springframework.security.oauth2.client.authentication.ui.AbstractLoginPageGeneratingFilter.ERROR_PARAMETER_NAME;
import static org.springframework.security.oauth2.client.authentication.ui.AbstractLoginPageGeneratingFilter.LOGOUT_PARAMETER_NAME;

/**
 * @author Joe Grandja
 */
public final class OAuth2ClientSecurityConfigurer<B extends HttpSecurityBuilder<B>> extends
		AbstractHttpConfigurer<OAuth2ClientSecurityConfigurer<B>, B> {

	private AuthorizationRequestRedirectFilterConfigurer<B> authorizationRequestRedirectFilterConfigurer;

	private AuthorizationCodeGrantFilterConfigurer<B> authorizationCodeGrantFilterConfigurer;

	private boolean loginPageFilterEnabled;


	public OAuth2ClientSecurityConfigurer() {
		this.authorizationRequestRedirectFilterConfigurer = new AuthorizationRequestRedirectFilterConfigurer<>();
		this.authorizationCodeGrantFilterConfigurer = new AuthorizationCodeGrantFilterConfigurer<>();
		this.loginPageFilterEnabled = true;
	}

	public OAuth2ClientSecurityConfigurer<B> clients(ClientRegistration... clientRegistrations) {
		Assert.notEmpty(clientRegistrations, "clientRegistrationRepository cannot be empty");
		return clients(new InMemoryClientRegistrationRepository(Arrays.asList(clientRegistrations)));
	}

	public OAuth2ClientSecurityConfigurer<B> clients(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		Assert.notEmpty(clientRegistrationRepository.getRegistrations(), "clientRegistrationRepository cannot be empty");
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	public OAuth2ClientSecurityConfigurer<B> clientsPage(String clientsPage) {
		Assert.notNull(clientsPage, "clientsPage cannot be null");
		this.authorizationCodeGrantFilterConfigurer.clientsPage(clientsPage);
		this.loginPageFilterEnabled = false;
		return this;
	}

	public OAuth2ClientSecurityConfigurer<B> authorizationEndpoint(String authorizationUri) {
		Assert.notNull(authorizationUri, "authorizationUri cannot be null");
		this.authorizationRequestRedirectFilterConfigurer.authorizationProcessingUri(authorizationUri);
		return this;
	}

	public OAuth2ClientSecurityConfigurer<B> authorizationRequestBuilder(AuthorizationRequestUriBuilder authorizationRequestBuilder) {
		Assert.notNull(authorizationRequestBuilder, "authorizationRequestBuilder cannot be null");
		this.authorizationRequestRedirectFilterConfigurer.authorizationRequestBuilder(authorizationRequestBuilder);
		return this;
	}

	public OAuth2ClientSecurityConfigurer<B> authorizationCodeGrantTokenExchanger(
			AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> authorizationCodeGrantTokenExchanger) {

		Assert.notNull(authorizationCodeGrantTokenExchanger, "authorizationCodeGrantTokenExchanger cannot be null");
		this.authorizationCodeGrantFilterConfigurer.authorizationCodeGrantTokenExchanger(authorizationCodeGrantTokenExchanger);
		return this;
	}

	public OAuth2ClientSecurityConfigurer<B> userInfoEndpointService(UserInfoUserDetailsService userInfoEndpointService) {
		Assert.notNull(userInfoEndpointService, "userInfoEndpointService cannot be null");
		this.authorizationCodeGrantFilterConfigurer.userInfoUserDetailsService(userInfoEndpointService);
		return this;
	}

	@Override
	public void init(B http) throws Exception {
		this.authorizationRequestRedirectFilterConfigurer.setBuilder(http);
		this.authorizationCodeGrantFilterConfigurer.setBuilder(http);

		this.authorizationRequestRedirectFilterConfigurer.init(http);
		this.authorizationCodeGrantFilterConfigurer.init(http);
	}

	@Override
	public void configure(B http) throws Exception {
		this.authorizationRequestRedirectFilterConfigurer.configure(http);
		this.authorizationCodeGrantFilterConfigurer.configure(http);
		this.initDefaultLoginFilter(http);
	}

	public static OAuth2ClientSecurityConfigurer<HttpSecurity> oauth2Client() {
		return new OAuth2ClientSecurityConfigurer<>();
	}

	protected static ClientRegistrationRepository getDefaultClientRegistrationRepository(ApplicationContext context) {
		Map<String, ClientRegistration> clientRegistrations = context.getBeansOfType(ClientRegistration.class);
		ClientRegistrationRepository clientRegistrationRepository = new InMemoryClientRegistrationRepository(
				clientRegistrations.values().stream().collect(Collectors.toList()));
		return clientRegistrationRepository;
	}

	private void initDefaultLoginFilter(B http) {
		if (!this.loginPageFilterEnabled) {
			return;
		}

		DefaultOAuth2LoginPageGeneratingFilter loginPageGeneratingFilter = new DefaultOAuth2LoginPageGeneratingFilter(
				this.getBuilder().getSharedObject(ClientRegistrationRepository.class));
		String clientsPage = this.authorizationCodeGrantFilterConfigurer.getClientsPage();
		loginPageGeneratingFilter.setLoginPageUrl(clientsPage);
		loginPageGeneratingFilter.setLogoutSuccessUrl(clientsPage + "?" + LOGOUT_PARAMETER_NAME);
		loginPageGeneratingFilter.setFailureUrl(clientsPage + "?" + ERROR_PARAMETER_NAME);
		loginPageGeneratingFilter.setAuthenticationUrl(
				this.authorizationRequestRedirectFilterConfigurer.getAuthorizationProcessingUri());
		loginPageGeneratingFilter.setLoginEnabled(true);

		// TODO Temporary workaround
		// 		Remove this after we add an order in FilterComparator for DefaultOAuth2LoginPageGeneratingFilter
		this.addObjectPostProcessor(new OrderedFilterWrappingPostProcessor());

		http.addFilter(this.postProcess(loginPageGeneratingFilter));
	}

	// TODO Temporary workaround
	// 		Remove this after we add an order in FilterComparator for DefaultOAuth2LoginPageGeneratingFilter
	private final class OrderedFilterWrappingPostProcessor implements ObjectPostProcessor<Object> {

		@SuppressWarnings({ "rawtypes", "unchecked" })
		public Object postProcess(final Object delegateFilter) {
			DefaultLoginPageGeneratingFilter orderedFilter = new DefaultLoginPageGeneratingFilter() {

				@Override
				public void doFilter(ServletRequest request, ServletResponse response,
									 FilterChain chain) throws IOException, ServletException {

					((DefaultOAuth2LoginPageGeneratingFilter)delegateFilter).doFilter(request, response, chain);
				}
			};
			return orderedFilter;
		}
	}
}