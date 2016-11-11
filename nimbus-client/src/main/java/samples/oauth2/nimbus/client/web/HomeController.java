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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.config.ClientConfigurationRepository;
import org.springframework.security.oidc.rp.authentication.OpenIDConnectUserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

/**
 * @author Joe Grandja
 */
@Controller
public class HomeController {

	@Autowired
	protected ClientConfigurationRepository clientConfigurationRepository;

	@RequestMapping("/")
	public String index(Model model) {
		model.addAttribute("clientConfigurations", clientConfigurationRepository.getConfigurations());
		return "index";
	}

	@RequestMapping("/oauth2/client/google")
	public String googleClientApp(Model model, @AuthenticationPrincipal OpenIDConnectUserDetails user) {
		populateAuthenticationAttrs(model, user);
		return "authorized";
	}

	@RequestMapping("/oauth2/client/github")
	public String githubClientApp(Model model, @AuthenticationPrincipal OpenIDConnectUserDetails user) {
		populateAuthenticationAttrs(model, user);
		return "authorized";
	}

	public void populateAuthenticationAttrs(Model model, OpenIDConnectUserDetails user) {
		model.addAttribute("subject_identifier", user.getIdentifier());
		model.addAttribute("user_name", user.getName());
	}
}