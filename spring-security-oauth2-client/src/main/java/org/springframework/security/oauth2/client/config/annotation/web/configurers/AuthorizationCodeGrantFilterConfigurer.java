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
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationProvider;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.nimbus.NimbusAuthorizationCodeGrantTokenExchanger;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.filter.AuthorizationCodeGrantProcessingFilter;
import org.springframework.security.oauth2.client.filter.AuthorizationUtil;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.oauth2.client.userdetails.nimbus.NimbusUserInfoUserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantTokenExchanger;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * @author Joe Grandja
 */
public final class AuthorizationCodeGrantFilterConfigurer<H extends HttpSecurityBuilder<H>> extends
		AbstractAuthenticationFilterConfigurer<H, AuthorizationCodeGrantFilterConfigurer<H>, AuthorizationCodeGrantProcessingFilter> {

	public static final String DEFAULT_LOGIN_PAGE_URI = "/login/oauth2";

	private AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> authorizationCodeGrantTokenExchanger;

	private UserInfoUserDetailsService userInfoUserDetailsService;


	public AuthorizationCodeGrantFilterConfigurer() {
		super(new AuthorizationCodeGrantProcessingFilter(), null);
	}

	public AuthorizationCodeGrantFilterConfigurer<H> clientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		return this;
	}

	public AuthorizationCodeGrantFilterConfigurer<H> authorizationCodeGrantTokenExchanger(
			AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> authorizationCodeGrantTokenExchanger) {
		this.authorizationCodeGrantTokenExchanger = authorizationCodeGrantTokenExchanger;
		return this;
	}

	public AuthorizationCodeGrantFilterConfigurer<H> userInfoUserDetailsService(UserInfoUserDetailsService userInfoUserDetailsService) {
		this.userInfoUserDetailsService = userInfoUserDetailsService;
		return this;
	}

	@Override
	public void init(H http) throws Exception {
		if (!this.isCustomLoginPage()) {
			// Override the default login page /login (if not already configured)
			this.loginPage(DEFAULT_LOGIN_PAGE_URI);
			this.permitAll();
		}

		AuthorizationCodeGrantAuthenticationProvider authenticationProvider = new AuthorizationCodeGrantAuthenticationProvider(
				this.getAuthorizationCodeGrantTokenExchanger(), this.getUserInfoUserDetailsService());
		authenticationProvider = this.postProcess(authenticationProvider);
		http.authenticationProvider(authenticationProvider);

		super.init(http);
	}

	@Override
	public void configure(H http) throws Exception {
		AuthorizationCodeGrantProcessingFilter authFilter = this.getAuthenticationFilter();
		authFilter.setClientRegistrationRepository(this.getClientRegistrationRepository());

		// TODO Temporary workaround
		// 		Remove this after we add an order in FilterComparator for AuthorizationCodeGrantProcessingFilter
		this.addObjectPostProcessor(new OrderedFilterWrappingPostProcessor());

		super.configure(http);
	}

	@Override
	public AuthorizationCodeGrantFilterConfigurer<H> loginPage(String loginPage) {
		return super.loginPage(loginPage);
	}

	@Override
	protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
		// NOTE: loginProcessingUrl is purposely ignored as the matcher depends
		// 			on specific request parameters instead of the requestUri
		return AuthorizationUtil::isAuthorizationCodeGrantResponse;
	}

	private ClientRegistrationRepository getClientRegistrationRepository() {
		ClientRegistrationRepository clientRegistrationRepository = this.getBuilder().getSharedObject(ClientRegistrationRepository.class);
		if (clientRegistrationRepository == null) {
			ApplicationContext context = this.getBuilder().getSharedObject(ApplicationContext.class);
			Map<String, ClientRegistration> clientRegistrations = context.getBeansOfType(ClientRegistration.class);
			Assert.state(!CollectionUtils.isEmpty(clientRegistrations),
					"There must be at least 1 bean configured of type " + ClientRegistration.class.getName());
			clientRegistrationRepository = new InMemoryClientRegistrationRepository(
					clientRegistrations.values().stream().collect(Collectors.toList()));
			this.getBuilder().setSharedObject(ClientRegistrationRepository.class, clientRegistrationRepository);
		}
		return clientRegistrationRepository;
	}

	private AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> getAuthorizationCodeGrantTokenExchanger() {
		if (this.authorizationCodeGrantTokenExchanger == null) {
			this.authorizationCodeGrantTokenExchanger = new NimbusAuthorizationCodeGrantTokenExchanger();
		}
		return this.authorizationCodeGrantTokenExchanger;
	}

	private UserInfoUserDetailsService getUserInfoUserDetailsService() {
		if (this.userInfoUserDetailsService == null) {
			this.userInfoUserDetailsService = new NimbusUserInfoUserDetailsService();
		}
		return this.userInfoUserDetailsService;
	}

	public static AuthorizationCodeGrantFilterConfigurer<HttpSecurity> authorizationCodeGrant() {
		AuthorizationCodeGrantFilterConfigurer<HttpSecurity> configurer = new AuthorizationCodeGrantFilterConfigurer<>();

		return configurer;
	}

	// TODO Temporary workaround
	// 		Remove this after we add an order in FilterComparator for AuthorizationCodeGrantProcessingFilter
	private final class OrderedFilterWrappingPostProcessor implements ObjectPostProcessor<Object> {

		@SuppressWarnings({ "rawtypes", "unchecked" })
		public Object postProcess(final Object delegateFilter) {
			UsernamePasswordAuthenticationFilter orderedFilter = new UsernamePasswordAuthenticationFilter() {
				@Override
				public void doFilter(ServletRequest request, ServletResponse response,
									 FilterChain chain) throws IOException, ServletException {

					((AuthorizationCodeGrantProcessingFilter)delegateFilter).doFilter(request, response, chain);
				}
			};
			return orderedFilter;
		}

	}
}