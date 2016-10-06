# OAuth2 Samples

**NOTE:** Before you run any of the samples, you must complete the prerequisite steps.

## Prerequisite Steps

- Register your client (web) application using [Google API Console](https://console.developers.google.com/). __NOTE:__ For the __Authorized Redirect URI__ enter _http://localhost:8080/oauth2callback/google_
- After registering your client application, enable the __Google Calendar API__ under your Google account. The sample app is requesting one of the supported scopes for the Google Calendar API.
- Register another client (web) application using [GitHub Developer Applications](https://github.com/settings/developers). __NOTE:__ For the __Authorized Redirect URI__ enter _http://localhost:8080/oauth2callback/github_
- The final step is to enter the Client Id and Client Secret for your registered clients (google and github) in `application.yml` for each sample application.

## Nimbus OAuth Client

This sample demonstrates the use of the [Nimbus OAuth 2.0 SDK](http://connect2id.com/products/nimbus-oauth-openid-connect-sdk).

## Google OAuth Client

This sample demonstrates the use of the [Google OAuth Client Library](https://developers.google.com/api-client-library/java/google-oauth-java-client/).

## Apache Oltu OAuth Client

This sample demonstrates the use of the [Apache Oltu OAuth Client](http://oltu.apache.org/source-repository.html).
