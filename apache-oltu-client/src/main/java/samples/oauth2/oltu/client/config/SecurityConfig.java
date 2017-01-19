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
package samples.oauth2.oltu.client.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authentication.oltu.OltuAuthorizationCodeGrantTokenExchanger;
import org.springframework.security.oauth2.client.filter.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.filter.oltu.OltuAuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.oauth2.client.userdetails.oltu.OltuUserInfoUserDetailsService;

import java.util.List;

import static org.springframework.security.oauth2.client.config.annotation.web.configurers.OAuth2ClientSecurityConfigurer.oauth2Client;

/**
 *
 * @author Joe Grandja
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
					.antMatchers("/favicon.ico").permitAll()
					.anyRequest().fullyAuthenticated()
					.and()
				.apply(oauth2Client()
						.authorizationRequestBuilder(authorizationRequestBuilder())
						.authorizationCodeGrantTokenExchanger(authorizationCodeGrantTokenExchanger())
						.userInfoEndpointService(userInfoEndpointService()));
	}
	// @formatter:on

	@ConfigurationProperties(prefix = "security.oauth2.client.google")
	@Bean
	public ClientRegistration googleClientRegistration() {
		return new ClientRegistration();
	}

	@ConfigurationProperties(prefix = "security.oauth2.client.github")
	@Bean
	public ClientRegistration githubClientRegistration() {
		return new ClientRegistration();
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository(List<ClientRegistration> clientRegistrations) {
		return new InMemoryClientRegistrationRepository(clientRegistrations);
	}

	private AuthorizationRequestUriBuilder authorizationRequestBuilder() {
		return new OltuAuthorizationRequestUriBuilder();
	}

	private AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> authorizationCodeGrantTokenExchanger() {
		return new OltuAuthorizationCodeGrantTokenExchanger();
	}

	private UserInfoUserDetailsService userInfoEndpointService() {
		return new OltuUserInfoUserDetailsService();
	}
}