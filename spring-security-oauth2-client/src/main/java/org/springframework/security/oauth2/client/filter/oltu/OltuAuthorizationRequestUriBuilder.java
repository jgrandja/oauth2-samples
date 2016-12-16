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
package org.springframework.security.oauth2.client.filter.oltu;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.springframework.security.oauth2.client.filter.AuthorizationRequestUriBuilder;
import org.springframework.security.oauth2.core.OAuth2Exception;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.stream.Collectors;

/**
 * TODO AuthorizationRequestUriBuilder and associated implementations seem redundant. May be removed
 *
 * @author Joe Grandja
 */
public class OltuAuthorizationRequestUriBuilder implements AuthorizationRequestUriBuilder {

	@Override
	public URI build(AuthorizationRequestAttributes authorizationRequestAttributes) {
		URI result;
		try {
			OAuthClientRequest authorizationRequest = OAuthClientRequest
					.authorizationLocation(authorizationRequestAttributes.getAuthorizeUri())
					.setClientId(authorizationRequestAttributes.getClientId())
					.setRedirectURI(authorizationRequestAttributes.getRedirectUri())
					.setResponseType(org.apache.oltu.oauth2.common.message.types.ResponseType.valueOf(
							authorizationRequestAttributes.getResponseType().value().toUpperCase()).toString())
					.setScope(authorizationRequestAttributes.getScope().stream().collect(Collectors.joining(" ")))
					.setState(authorizationRequestAttributes.getState())
					.buildQueryMessage();

			result = new URI(authorizationRequest.getLocationUri());

		} catch (OAuthSystemException sysex) {
			// TODO Throw "appropriate" exception for downstream handling
			throw new OAuth2Exception(sysex.getMessage(), sysex);
		} catch (URISyntaxException uriex) {
			// TODO Throw "appropriate" exception for downstream handling
			throw new OAuth2Exception(uriex.getMessage(), uriex);
		}

		return result;
	}
}