/*
 * Copyright 2012-2017 the original author or authors.
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
package samples.oauth2.google.client.web.servlet;

import org.springframework.boot.web.servlet.ServletContextInitializer;
import samples.oauth2.google.client.OAuthProvider;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.ServletRegistration;

/**
 * @author Joe Grandja
 */
public class DefaultWebApplicationInitializer implements ServletContextInitializer {

	@Override
	public void onStartup(ServletContext servletContext) throws ServletException {
		registerAuthorizationCodeFlowServlet(servletContext, OAuthProvider.GOOGLE);
		registerAuthorizationCodeFlowServlet(servletContext, OAuthProvider.GITHUB);
	}

	private void registerAuthorizationCodeFlowServlet(ServletContext servletContext, OAuthProvider provider) {
		ServletRegistration.Dynamic authorizationCodeFlowServlet =
				servletContext.addServlet(AuthorizationCodeFlowServlet.class.getSimpleName() + "." + provider.name(), new AuthorizationCodeFlowServlet());
		authorizationCodeFlowServlet.setLoadOnStartup(1);
		authorizationCodeFlowServlet.addMapping(AuthorizationCodeFlowUtil.AUTH_URI + "/" + provider.name().toLowerCase());

		ServletRegistration.Dynamic authorizationCodeFlowCallbackServlet =
				servletContext.addServlet(AuthorizationCodeFlowCallbackServlet.class.getSimpleName() + "." + provider.name(), new AuthorizationCodeFlowCallbackServlet());
		authorizationCodeFlowCallbackServlet.addMapping(AuthorizationCodeFlowUtil.REDIRECT_URI + "/" + provider.name().toLowerCase());
	}

}