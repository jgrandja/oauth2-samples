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
package samples.oauth2.oltu.client.web;

import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.GitHubTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthAccessTokenResponse;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.client.response.OAuthJSONAccessTokenResponse;
import org.apache.oltu.oauth2.common.message.types.GrantType;
import org.apache.oltu.oauth2.common.message.types.ResponseType;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriComponentsBuilder;
import samples.oauth2.oltu.client.OAuthClientConfig;
import samples.oauth2.oltu.client.OAuthProvider;

import javax.servlet.http.HttpServletRequest;
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
	private static final String AUTH_URI = "/authorize";
	private static final String REDIRECT_URI = "/oauth2callback";

	@Autowired
	private List<OAuthClientConfig> clientConfigs;

	@RequestMapping(value = AUTH_URI, method = RequestMethod.GET)
	public ResponseEntity<Void> authorize(@RequestParam String provider, HttpServletRequest request) {
		ResponseEntity<Void> response;

		try {
			OAuthClientConfig clientConfig = getClientConfig(provider);
			OAuthClientRequest oauthClientRequest = OAuthClientRequest
					.authorizationLocation(clientConfig.getAuthorizationUrl())
					.setClientId(clientConfig.getClientId())
					.setRedirectURI(buildRedirectUri(request, clientConfig))
					.setResponseType(ResponseType.CODE.toString())
					.setScope(clientConfig.getScopes().stream().collect(Collectors.joining(" ")))
					.buildQueryMessage();
			URI location = URI.create(oauthClientRequest.getLocationUri());
			response = status(HttpStatus.FOUND).location(location).build();
		} catch (Exception ex) {
			logger.error(ex.getMessage(), ex);
			throw new IllegalArgumentException(ex);
		}

		return response;
	}

	@RequestMapping(value = REDIRECT_URI + "/{provider}", method = RequestMethod.GET)
	public String authorizeCallback(@PathVariable String provider, HttpServletRequest request, Model model) {

		try {
			String code = OAuthAuthzResponse.oauthCodeAuthzResponse(request).getCode();
			OAuthClientConfig clientConfig = getClientConfig(provider);
			OAuthClientRequest oauthClientRequest = OAuthClientRequest
					.tokenLocation(clientConfig.getTokenUrl())
					.setGrantType(GrantType.AUTHORIZATION_CODE)
					.setClientId(clientConfig.getClientId())
					.setClientSecret(clientConfig.getClientSecret())
					.setRedirectURI(buildRedirectUri(request, clientConfig))
					.setCode(code)
					.setScope(clientConfig.getScopes().stream().collect(Collectors.joining(" ")))
					.buildBodyMessage();

			Class<? extends OAuthAccessTokenResponse> oauthTokenResponseClazz = OAuthAccessTokenResponse.class;
			if (OAuthProvider.GOOGLE.equals(clientConfig.getProvider())) {
				oauthTokenResponseClazz = OAuthJSONAccessTokenResponse.class;
			} else if (OAuthProvider.GITHUB.equals(clientConfig.getProvider())) {
				oauthTokenResponseClazz = GitHubTokenResponse.class;
			}
			OAuthClient oauthClient = new OAuthClient(new URLConnectionClient());
			OAuthAccessTokenResponse oauthTokenResponse = oauthClient.accessToken(oauthClientRequest, oauthTokenResponseClazz);

			model.addAttribute("accessToken", oauthTokenResponse.getAccessToken());

		} catch (Exception ex) {
			logger.error(ex.getMessage(), ex);
			throw new IllegalArgumentException(ex);
		}

		return "authorized";
	}

	@ExceptionHandler(Exception.class)
	public ResponseEntity<String> handleException(Exception ex) {
		ResponseEntity<String> response = ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(ex.getMessage());

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
}