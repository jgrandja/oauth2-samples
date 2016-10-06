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
package samples.oauth2.nimbus.client.web;

import com.nimbusds.oauth2.sdk.*;
import com.nimbusds.oauth2.sdk.auth.ClientAuthentication;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.State;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;
import samples.oauth2.nimbus.client.OAuthClientConfig;
import samples.oauth2.nimbus.client.OAuthProvider;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.Serializable;
import java.net.URI;
import java.util.List;
import java.util.stream.Collectors;

import static org.springframework.http.ResponseEntity.status;

/**
 * @author Joe Grandja
 */
@Controller
public class AuthorizationController {
	private static final Logger logger = LoggerFactory.getLogger(AuthorizationController.class);
	private static final String SESSION_CACHE_ATTR_NAME = AuthorizationController.class.getName() + ".SESSION_CACHE";
	private static final String AUTH_URI = "/authorize";
	private static final String REDIRECT_URI = "/oauth2callback";

	@Autowired
	private List<OAuthClientConfig> clientConfigs;

	@RequestMapping(value = AUTH_URI, method = RequestMethod.GET)
	public ResponseEntity<Void> authorize(@RequestParam String provider, HttpServletRequest request) {
		ResponseEntity<Void> response;

		try {
			OAuthClientConfig clientConfig = getClientConfig(provider);

			// The authorization endpoint of the server
			URI authEndpoint = new URI(clientConfig.getAuthorizationUrl());

			// The client identifier provisioned by the server
			ClientID clientId = new ClientID(clientConfig.getClientId());

			// The requested scope values for the token
			Scope scope = new Scope(clientConfig.getScopesAsArray());

			// The client callback URI, typically pre-registered with the server
			URI redirectUri = new URI(buildRedirectUri(request, clientConfig));

			// Generate random state string for pairing the response to the request
			State state = new State();

			// Save the state so we can validate it on the authorization response callback
			SessionCache sessionCache = new SessionCache();
			sessionCache.setState(state.getValue());
			saveSessionCache(sessionCache, request);

			// Build the request
			AuthorizationRequest authRequest = new AuthorizationRequest.Builder(
					new ResponseType(ResponseType.Value.CODE), clientId)
					.scope(scope)
					.state(state)
					.redirectionURI(redirectUri)
					.endpointURI(authEndpoint)
					.build();

			URI requestURI = authRequest.toURI();

			response = status(HttpStatus.FOUND).location(requestURI).build();

		} catch (Exception ex) {
			logger.error(ex.getMessage(), ex);
			throw new IllegalArgumentException(ex);
		}

		return response;
	}

	@RequestMapping(value = REDIRECT_URI + "/{provider}", method = RequestMethod.GET)
	public String authorizeCallback(@PathVariable String provider, HttpServletRequest request, Model model) {

		try {
			// Parse the authorization response from the callback URI
			AuthorizationResponse authResponse = AuthorizationResponse.parse(toURI(request));

			if (!authResponse.indicatesSuccess()) {
				AuthorizationErrorResponse authErrorResponse = (AuthorizationErrorResponse)authResponse;

				// The request was denied or some error may have occurred
				throw new IllegalArgumentException(authErrorResponse.getErrorObject().getDescription());
			}

			AuthorizationSuccessResponse authSuccessResponse = (AuthorizationSuccessResponse)authResponse;

			// The returned state parameter must match the one sent with the request
			SessionCache sessionCache = getSessionCache(request);
			if (sessionCache == null || !sessionCache.getState().equals(authSuccessResponse.getState().getValue())) {
				// Unexpected or tampered response
				throw new IllegalStateException("State does not match");
			}

			OAuthClientConfig clientConfig = getClientConfig(provider);

			// Construct the code grant from the code obtained from the authz endpoint
			// and the original callback URI used at the authz endpoint
			AuthorizationCode authCode = new AuthorizationCode(authSuccessResponse.getAuthorizationCode().getValue());
			URI redirectUri = new URI(buildRedirectUri(request, clientConfig));
			AuthorizationGrant authCodeGrant = new AuthorizationCodeGrant(authCode, redirectUri);

			// The credentials to authenticate the client at the token endpoint
			ClientID clientId = new ClientID(clientConfig.getClientId());
			Secret clientSecret = new Secret(clientConfig.getClientSecret());
			ClientAuthentication clientAuth = new ClientSecretBasic(clientId, clientSecret);

			// The token endpoint
			URI tokenEndpoint = new URI(clientConfig.getTokenUrl());

			// Make the token request
			TokenRequest tokenRequest = new TokenRequest(tokenEndpoint, clientAuth, authCodeGrant);

			TokenResponse tokenResponse = TokenResponse.parse(tokenRequest.toHTTPRequest().send());

			if (!tokenResponse.indicatesSuccess()) {
				// We got an error response
				TokenErrorResponse tokenErrorResponse = (TokenErrorResponse) tokenResponse;
				throw new IllegalArgumentException(tokenErrorResponse.getErrorObject().getDescription());
			}

			AccessTokenResponse accessTokenResponse = (AccessTokenResponse) tokenResponse;

			// Get the access token, the server may also return a refresh token
			AccessToken accessToken = accessTokenResponse.getTokens().getAccessToken();
			RefreshToken refreshToken = accessTokenResponse.getTokens().getRefreshToken();

			model.addAttribute("accessToken", accessToken.getValue());

		} catch (Exception ex) {
			logger.error(ex.getMessage(), ex);
			throw new IllegalArgumentException(ex);
		}

		return "authorized";
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<String> handleException(Exception ex) {
		ResponseEntity<String> response = status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());
		return response;
	}

	private String buildRedirectUri(HttpServletRequest request, OAuthClientConfig clientConfig) {
		String redirectUri = UriComponentsBuilder.newInstance()
									.scheme(request.getScheme())
									.host(request.getServerName())
									.port(request.getServerPort())
									.path(REDIRECT_URI)
									.path("/" + clientConfig.getProvider().name().toLowerCase())
									.toUriString();
		return redirectUri;
	}

	private OAuthClientConfig getClientConfig(String provider) {
		List<OAuthClientConfig> matchingClientConfigs =
				clientConfigs.stream()
						.filter(c -> c.getProvider().name().equalsIgnoreCase(provider))
						.collect(Collectors.toList());
		if (matchingClientConfigs.isEmpty()) {
			return getClientConfig(OAuthProvider.GOOGLE.name());		// Default to Google
		}
		return matchingClientConfigs.get(0);
	}

	private URI toURI(HttpServletRequest request) {
		return UriComponentsBuilder.fromHttpRequest(new ServletServerHttpRequest(request)).build().toUri();
	}

	private SessionCache getSessionCache(HttpServletRequest request) {
		SessionCache sessionCache = null;
		HttpSession session = request.getSession(false);
		if (session != null) {
			sessionCache = SessionCache.class.cast(session.getAttribute(SESSION_CACHE_ATTR_NAME));
		}
		return sessionCache;
	}

	private void saveSessionCache(SessionCache sessionCache, HttpServletRequest request) {
		HttpSession session = request.getSession();
		session.setAttribute(SESSION_CACHE_ATTR_NAME, sessionCache);
	}

	private class SessionCache implements Serializable {
		private String state;

		private String getState() {
			return state;
		}

		private void setState(String state) {
			this.state = state;
		}
	}
}