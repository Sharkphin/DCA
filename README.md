### DCA
The DCA extension, short for Discourse Community Authentication, is my first open-source extension! Over the next few weeks you will see many improvements to code and 
a great amount of customization! Fortunately I've made this extension in two days, so if you come across errors, please file an issue report.

### Blocks
#### `OnAuthenticated`
The `OnAuthenticated` event contains one parameter, `key` and is executed when the user has granted the application access to their community profile. 
The `key` parameter will give you an API key to use against the Discourse API. 

---

#### `OnDenied`
The `OnDenied` event executes when the user has denied permission to their community profile.

---

#### `Authenticate`
The `Authenticate` block contains two parameters, `base` and `scopes`.

For the *base* parameter, you're going to want to set it to the URL of the Discourse ran community.
For example, `https://community.kodular.io` without a slash at the end.

For the *scopes* parameter, you're going to want to set it as a list of scopes. The accepted scopes are `message_bus`, `one_time_password`, `read`, `session_info`, and `write`. 
These scopes will allow you to get a specific amount of data from the users profile using the API key against the Discourse API.
