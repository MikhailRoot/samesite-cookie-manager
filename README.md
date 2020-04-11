# SameSite Cookie Manager

This plugin overrides default WordPress authentication functions for PHP 7.3 
allowing to specify `SameSite`  Cookie's parameter: `None` \ `Lax` \ `Strict`

##Installation
1. Install as normal plugin uploading a zip file and activate,
2. In Word Press admin panel go to `Settings` -> `General`, and you'll see new setting  `Authentication SameSite Cookie parameter`
3. Set this setting to desired value and hit `Save Changes` - logout and login again and in Chrome dev tools in Cookies table you'll see your `SameSite` value applied to authentication Cookie.

## Important:
 This plugin manages SameSite cookie only for  `PHP 7.3` and above and doesn't have polyfills for previous PHP versions.
 
 The reason is that polyfills I've tried were not working reliably.
 
 PHP since `7.3` - has native support for SameSite parameter in new version of `setcookie()` function.
 
 So in general if you have a requirement to manage SameSite parameter for Cookie - it means you are already doing something complex and need to update to more recent php version will not scare you.
 
 In addition updating to PHP 7.3 will increase performance of your site. But be careful, some plugins\themes have still deprecated features used, so first test on local development environment with a new PHP version, especially if you are upgrading from PHP 5.x .