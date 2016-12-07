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
package samples.oauth2.nimbus.client.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.ObjectPostProcessor;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationProvider;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.client.config.InMemoryClientConfigurationRepository;
import org.springframework.security.oauth2.client.filter.AuthorizationCodeGrantProcessingFilter;
import org.springframework.security.oauth2.client.filter.AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.filter.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.filter.AuthorizationSuccessResponseHandler;
import org.springframework.security.oauth2.client.filter.nimbus.NimbusAuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.filter.nimbus.NimbusAuthorizationSuccessResponseHandler;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.oauth2.client.userdetails.nimbus.NimbusUserInfoUserDetailsService;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;

import javax.servlet.Filter;
import java.util.List;

/**
 * TODO
 * NOTE:
 * 		Most of the configuration in this class will eventually go into a SecurityConfigurer,
 * 		for example, OAuth2ClientSecurityConfigurer and then applied to HttpSecurity.
 *
 * @author Joe Grandja
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
	private static final String LOGIN_URL = "/login/oauth2";

	@Autowired
	protected ClientConfigurationRepository clientConfigurationRepository;

	@Autowired
	protected AuthorizationRequestUriBuilder authorizationRequestUriBuilder;

	@Autowired
	protected AuthorizationSuccessResponseHandler authorizationSuccessResponseHandler;

	@Autowired
	protected ObjectPostProcessor objectPostProcessor;

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
					.antMatchers(LOGIN_URL).permitAll()
					.anyRequest().fullyAuthenticated()
					.and()
				.exceptionHandling()
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(LOGIN_URL))
					.and()
				.addFilterAfter(authorizationRequestRedirectFilter(), AbstractPreAuthenticatedProcessingFilter.class)
				.addFilterAfter(authorizationCodeGrantProcessingFilter(), AuthorizationRequestRedirectFilter.class);
	}
	// @formatter:on

	// @formatter:off
	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.authenticationProvider(oauth2AuthenticationProvider());
	}
	// @formatter:on

	@ConfigurationProperties(prefix = "security.oauth2.client.google")
	@Bean
	public ClientConfiguration googleClientConfiguration() {
		return new ClientConfiguration();
	}

	@ConfigurationProperties(prefix = "security.oauth2.client.github")
	@Bean
	public ClientConfiguration githubClientConfiguration() {
		return new ClientConfiguration();
	}

	@Bean
	public ClientConfigurationRepository clientConfigurationRepository(List<ClientConfiguration> clientConfigurations) {
		return new InMemoryClientConfigurationRepository(clientConfigurations);
	}

	@Bean
	public AuthenticationProvider oauth2AuthenticationProvider() {
		return new OAuth2AuthenticationProvider(userInfoUserDetailsService());
	}



	// ********************************************* //
	// *****  Nimbus-specific implementations  ***** //
	// ********************************************* //
	@Bean
	public AuthorizationRequestUriBuilder authorizationRequestUriBuilder() {
		return new NimbusAuthorizationRequestUriBuilder();
	}

	@Bean
	public AuthorizationSuccessResponseHandler authorizationSuccessResponseHandler(){
		return new NimbusAuthorizationSuccessResponseHandler();
	}

	@Bean
	public UserInfoUserDetailsService userInfoUserDetailsService() {
		return new NimbusUserInfoUserDetailsService();
	}
	// ********************************************* //
	// *****  Nimbus-specific implementations  ***** //
	// ********************************************* //



	private Filter authorizationRequestRedirectFilter() throws Exception {
		AuthorizationRequestRedirectFilter authorizationRequestRedirectFilter =
				new AuthorizationRequestRedirectFilter(
						LOGIN_URL,
						this.clientConfigurationRepository,
						this.authorizationRequestUriBuilder);

		// TODO This is temporary until we have a SecurityConfigurer
		this.objectPostProcessor.postProcess(authorizationRequestRedirectFilter);

		return authorizationRequestRedirectFilter;
	}

	private Filter authorizationCodeGrantProcessingFilter() throws Exception {
		AuthorizationCodeGrantProcessingFilter authorizationCodeGrantProcessingFilter =
				new AuthorizationCodeGrantProcessingFilter(
						this.clientConfigurationRepository,
						this.authorizationSuccessResponseHandler,
						this.authenticationManager());

		// TODO This is temporary until we have a SecurityConfigurer
		this.objectPostProcessor.postProcess(authorizationCodeGrantProcessingFilter);

		return authorizationCodeGrantProcessingFilter;
	}
}