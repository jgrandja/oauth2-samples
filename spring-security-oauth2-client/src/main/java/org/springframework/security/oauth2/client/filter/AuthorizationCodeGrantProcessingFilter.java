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

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2Attributes;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.oauth2.core.protocol.AuthorizationCodeGrantAuthorizationResponseAttributes;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.protocol.ErrorResponseAttributes;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.net.URI;

import static org.springframework.security.oauth2.client.filter.AuthorizationUtil.*;


/**
 * Handles an OAuth 2.0 Authorization Response for the Authorization Code Grant flow.
 *
 * @author Joe Grandja
 */
public class AuthorizationCodeGrantProcessingFilter extends AbstractAuthenticationProcessingFilter {
	private ClientRegistrationRepository clientRegistrationRepository;

	public AuthorizationCodeGrantProcessingFilter() {
		super(AuthorizationUtil::isAuthorizationCodeGrantResponse);
	}

	@Override
	public void afterPropertiesSet() {
		super.afterPropertiesSet();
		Assert.notNull(this.clientRegistrationRepository, "clientRegistrationRepository must be specified");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		if (isAuthorizationCodeGrantError(request)) {
			// The authorization request was denied or some error occurred
			ErrorResponseAttributes authorizationErrorAttributes = parseErrorAttributes(request);

			// TODO Throw OAuth2-specific exception (it should extend AuthenticationServiceException)
			// We should also find the matching Authorization Request using the 'state' parameter and
			// pass this into the exception for more context info when handling
			throw new AuthenticationServiceException("Authorization error: " + authorizationErrorAttributes.getErrorCode());
		}

		AuthorizationRequestAttributes matchingAuthorizationRequest = this.resolveAuthorizationRequest(request);

		ClientRegistration clientRegistration = this.clientRegistrationRepository.getRegistrationByClientId(
				matchingAuthorizationRequest.getClientId());

		AuthorizationCodeGrantAuthorizationResponseAttributes authorizationCodeGrantAttributes =
				parseAuthorizationCodeGrantAttributes(request);

		AuthorizationCodeGrantAuthenticationToken authRequest = new AuthorizationCodeGrantAuthenticationToken(
				authorizationCodeGrantAttributes.getCode(), clientRegistration);

		authRequest.setDetails(this.authenticationDetailsSource.buildDetails(request));

		Authentication authenticated = this.getAuthenticationManager().authenticate(authRequest);

		return authenticated;
	}

	protected AuthorizationRequestAttributes resolveAuthorizationRequest(HttpServletRequest request) {
		AuthorizationRequestAttributes authorizationRequest = AuthorizationUtil.getAuthorizationRequest(request);
		if (authorizationRequest == null) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("Unable to resolve matching authorization request");
		}
		this.assertMatchingAuthorizationRequest(request, authorizationRequest);
		return authorizationRequest;
	}

	protected void assertMatchingAuthorizationRequest(HttpServletRequest request, AuthorizationRequestAttributes authorizationRequest) {
		String state = request.getParameter(OAuth2Attributes.STATE);
		if (!authorizationRequest.getState().equals(state)) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("Invalid state parameter");
		}

		URI redirectUri = URI.create(authorizationRequest.getRedirectUri());
		if (!request.getRequestURI().equals(redirectUri.getPath())) {
			// TODO Throw OAuth2-specific exception for downstream handling
			throw new OAuth2Exception("Invalid redirect_uri parameter");
		}
	}

	public final void setClientRegistrationRepository(ClientRegistrationRepository clientRegistrationRepository) {
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}
}