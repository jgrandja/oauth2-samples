# OAuth2 Samples

## Google OAuth Client

This sample demonstrates the use of the [Google OAuth Client Library](https://developers.google.com/api-client-library/java/google-oauth-java-client/).

Before you run the sample, you must complete the following steps:
- Register your client (web) application using [Google API Console](https://console.developers.google.com/). __NOTE:__ For the __Authorized Redirect URI__ enter _http://localhost:8080/oauth2callback_
- After registering your client application, enable the __Google Calendar API__ under your Google account. The sample app is requesting one of the supported scopes for the Google Calendar API.
- The final step is to enter the Client Id and Client Secret of your registered client in the class `samples.oauth2.google.client.web.servlet.AuthorizationCodeFlowConfig`
