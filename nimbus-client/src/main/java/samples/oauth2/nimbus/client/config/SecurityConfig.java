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
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.oauth2.client.config.ClientConfiguration;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oauth2.client.config.InMemoryClientConfigurationRepository;
import org.springframework.security.oauth2.client.context.ClientContextRepository;
import org.springframework.security.oauth2.client.context.ClientContextResolver;
import org.springframework.security.oauth2.client.context.DefaultClientContextResolver;
import org.springframework.security.oauth2.client.context.HttpSessionClientContextRepository;
import org.springframework.security.oauth2.client.filter.*;
import org.springframework.security.oidc.rp.authentication.NimbusAuthenticationUserDetailsService;
import org.springframework.security.oidc.rp.authentication.OpenIDConnectAuthenticationProvider;
import org.springframework.security.oidc.rp.authentication.OpenIDConnectAuthenticationToken;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.Filter;
import java.util.List;

/**
 * @author Joe Grandja
 */
@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	protected ClientConfigurationRepository clientConfigurationRepository;

	@Autowired
	protected AuthorizationRequestRedirectStrategy authorizationRequestRedirectStrategy;

	@Autowired
	protected AuthorizationResponseHandler authorizationResponseHandler;

	// @formatter:off
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.authorizeRequests()
					.antMatchers("/", "/oauth2/client/**").permitAll()
					.anyRequest().authenticated()
					.and()
				.formLogin()
					.and()
				.addFilterBefore(authorizationCodeGrantFlowFilter(), UsernamePasswordAuthenticationFilter.class);
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
	public ClientContextRepository clientContextRepository() {
		return new HttpSessionClientContextRepository();
	}

	@Bean
	public ClientContextResolver clientContextResolver(
			ClientContextRepository clientContextRepository, ClientConfigurationRepository clientConfigurationRepository) {

		DefaultClientContextResolver clientContextResolver =
				new DefaultClientContextResolver(clientContextRepository, clientConfigurationRepository);
		return clientContextResolver;
	}

	@Bean
	public AuthenticationProvider openIDConnectAuthenticationProvider() {
		return new OpenIDConnectAuthenticationProvider(nimbusAuthenticationUserDetailsService());
	}

	@Bean
	public AuthorizationRequestRedirectStrategy nimbusAuthorizationRequestRedirectStrategy(
			ClientContextResolver clientContextResolver, ClientContextRepository clientContextRepository) {

		NimbusAuthorizationRequestRedirectStrategy authorizationRequestRedirectStrategy =
				new NimbusAuthorizationRequestRedirectStrategy(clientContextResolver, clientContextRepository);
		return authorizationRequestRedirectStrategy;
	}

	@Bean
	public AuthorizationResponseHandler nimbusAuthorizationResponseHandler(
			ClientContextResolver clientContextResolver, ClientContextRepository clientContextRepository) throws Exception {

		NimbusAuthorizationResponseHandler authorizationResponseHandler =
				new NimbusAuthorizationResponseHandler(clientContextResolver, clientContextRepository, this.authenticationManager());
		return authorizationResponseHandler;
	}

	@Bean
	public AuthenticationUserDetailsService<OpenIDConnectAuthenticationToken> nimbusAuthenticationUserDetailsService() {
		return new NimbusAuthenticationUserDetailsService();
	}

	private Filter authorizationCodeGrantFlowFilter() throws Exception {
		AuthorizationCodeGrantFlowProcessingFilter authorizationCodeGrantFlowFilter =
				new AuthorizationCodeGrantFlowProcessingFilter(
						this.clientConfigurationRepository,
						this.authorizationRequestRedirectStrategy,
						this.authorizationResponseHandler,
						this.authenticationManager());

		return authorizationCodeGrantFlowFilter;
	}

}