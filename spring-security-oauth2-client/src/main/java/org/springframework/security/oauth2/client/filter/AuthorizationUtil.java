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

import org.springframework.security.oauth2.core.OAuth2Attributes;
import org.springframework.security.oauth2.core.protocol.AuthorizationCodeGrantAuthorizationResponseAttributes;
import org.springframework.security.oauth2.core.protocol.AuthorizationRequestAttributes;
import org.springframework.security.oauth2.core.protocol.ErrorResponseAttributes;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * @author Joe Grandja
 */
public class AuthorizationUtil {
	static final String SAVED_AUTHORIZATION_REQUEST = "SPRING_SECURITY_OAUTH2_SAVED_AUTHORIZATION_REQUEST";

	static void saveAuthorizationRequest(HttpServletRequest request, AuthorizationRequestAttributes authorizationRequest) {
		HttpSession session = request.getSession();
		session.setAttribute(SAVED_AUTHORIZATION_REQUEST, authorizationRequest);
	}

	static AuthorizationRequestAttributes getAuthorizationRequest(HttpServletRequest request) {
		AuthorizationRequestAttributes authorizationRequest = null;
		HttpSession session = request.getSession(false);
		if (session != null) {
			authorizationRequest = (AuthorizationRequestAttributes) session.getAttribute(SAVED_AUTHORIZATION_REQUEST);
		}
		return authorizationRequest;
	}

	static boolean isAuthorizationCodeGrantSuccess(HttpServletRequest request) {
		return !StringUtils.isEmpty(request.getParameter(OAuth2Attributes.CODE)) &&
				!StringUtils.isEmpty(request.getParameter(OAuth2Attributes.STATE));
	}

	static AuthorizationCodeGrantAuthorizationResponseAttributes parseAuthorizationCodeGrantAttributes(HttpServletRequest request) {
		AuthorizationCodeGrantAuthorizationResponseAttributes result;

		String code = request.getParameter(OAuth2Attributes.CODE);
		Assert.hasText(code, OAuth2Attributes.CODE + " attribute is required");

		String state = request.getParameter(OAuth2Attributes.STATE);

		result = new AuthorizationCodeGrantAuthorizationResponseAttributes(code, state);

		return result;
	}

	static boolean isAuthorizationCodeGrantError(HttpServletRequest request) {
		return !StringUtils.isEmpty(request.getParameter(OAuth2Attributes.ERROR)) &&
				!StringUtils.isEmpty(request.getParameter(OAuth2Attributes.STATE));
	}

	static ErrorResponseAttributes parseErrorAttributes(HttpServletRequest request) {
		ErrorResponseAttributes result;

		String error = request.getParameter(OAuth2Attributes.ERROR);
		Assert.hasText(error, OAuth2Attributes.ERROR + " attribute is required");
		// TODO Validate - ensure 'error' is a valid code as per spec

		String errorDescription = request.getParameter(OAuth2Attributes.ERROR_DESCRIPTION);

		URI errorUri = null;
		String errorUriStr = request.getParameter(OAuth2Attributes.ERROR_URI);
		if (!StringUtils.isEmpty(errorUriStr)) {
			try {
				errorUri = new URI(errorUriStr);
			} catch (URISyntaxException ex) {
				throw new IllegalArgumentException("Invalid " + OAuth2Attributes.ERROR_URI + ": " + errorUriStr, ex);
			}
		}

		String state = request.getParameter(OAuth2Attributes.STATE);

		result = new ErrorResponseAttributes(error, errorDescription, errorUri, state);

		return result;
	}

	public static boolean isAuthorizationCodeGrantResponse(HttpServletRequest request) {
		return isAuthorizationCodeGrantSuccess(request) || isAuthorizationCodeGrantError(request);
	}
}