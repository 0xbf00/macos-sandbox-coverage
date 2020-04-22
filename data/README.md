The `data/` subdirectory contains the general sandboxing profile that is used as the ultimate matching target.

It is generated from a reduced, _generalised_ `Container.plist` file. Compared to for example `Calculator.app`'s metadata file, the following changes were made:

1. Removes `Identity` data
2. Removes `SandboxProfileData` data
3. Removes all entitlements except for the `com.apple.security.app-sandbox` entitlement, as this entitlement is shared by all sandboxed apps.
4. Under `SandboxProfileDataValidationParametersKey`, replaces all concrete paths with placeholder values such as `$_HOME$`
5. Under `SandboxProfileDataValidationRedirectablePathsKey`, replaces the user portion of the path with `$_HOME$`
6. Under `SandboxProfileDataValidationSnippetDictionariesKey`, removes all sandbox snippets but the `application.sb` and `system.sb` snippets. These snippets are included in every sandboxed app.

Use [`simbple`](https://github.com/0xbf00/simbple) to do this:

```sh
cd data/
simbple com.generic.container/Container.plist --scheme > generic_profile.sb
simbple com.generic.container/Container.plist --json > generic_profile.json
```

Note: the supplied general sandbox profile was generated on macOS 10.14.6. If you intend to use a different version of macOS, you'll need to generate your own generic profiles!