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

import org.springframework.security.oauth2.core.*;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.net.URI;
import java.net.URISyntaxException;

/**
 * @author Joe Grandja
 */
class AuthorizationUtil {

	static boolean isAuthorizationSuccess(HttpServletRequest request) {
		return !StringUtils.isEmpty(request.getParameter(OAuth2Attributes.CODE)) &&
				!StringUtils.isEmpty(request.getParameter(OAuth2Attributes.STATE));
	}

	static AuthorizationSuccessResponseAttributes parseAuthorizationSuccessAttributes(HttpServletRequest request) {
		AuthorizationSuccessResponseAttributes result;

		String code = request.getParameter(OAuth2Attributes.CODE);
		Assert.hasText(code, OAuth2Attributes.CODE + " attribute is required");

		String state = request.getParameter(OAuth2Attributes.STATE);

		result = new DefaultAuthorizationSuccessResponseAttributes(code, state);

		return result;
	}

	static boolean isAuthorizationError(HttpServletRequest request) {
		return !StringUtils.isEmpty(request.getParameter(OAuth2Attributes.ERROR));
	}

	static AuthorizationErrorResponseAttributes parseAuthorizationErrorAttributes(HttpServletRequest request) {
		AuthorizationErrorResponseAttributes result;

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

		result = new DefaultAuthorizationErrorResponseAttributes(error, state, errorDescription, errorUri);

		return result;
	}

	static boolean isAuthorizationResponse(HttpServletRequest request) {
		return isAuthorizationSuccess(request) || isAuthorizationError(request);
	}
}