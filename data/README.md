# Complementary Data

The `data/` subdirectory contains generic profiles, templates, examples, and other stuff we might want to keep an archive of.

## Generic Sandbox Profiles

The `data/` subdirectory contains the general sandboxing profile that is used as the ultimate matching target.

It is generated from a reduced, _generalised_ `Container.plist` file. Compared to for example `Calculator.app`'s metadata file, the following changes were made:

1. Removes `Identity` data
2. Removes `SandboxProfileData` data
3. Removes all entitlements except for the `com.apple.security.app-sandbox` entitlement, as this entitlement is shared by all sandboxed apps.
4. Under `Parameters`, replaces all concrete paths with placeholder values such as `$_HOME$`
5. Under `RedirectablePaths`, replaces the user portion of the path with `$_HOME$`
6. Turn `SystemImages` into an empty array.

Use [`simbple`](https://github.com/0xbf00/simbple) to do this:

```sh
cd data/generic_profiles/
export PLATFORM="$(sw_vers -productVersion)-$(sw_vers -buildVersion)"
simbple "$PLATFORM.plist" --scheme > "$PLATFORM.sb"
simbple "$PLATFORM.plist" --JSON > "$PLATFORM.sb"
```

Note: depending on your version of macOS you might need to generate your own generic profiles!

## Templates

The templates are used for generating reports. They are created with the [Jinja](http://jinja.palletsprojects.com) template language.

## IOKit Mappings

The `iomap/` subdirectory contains platform-specific mappings from IOKit services to clients. The mappings in this directory are not directly used by the matcher. The mappings the matcher actually uses are defined in `matching-core/sandbox_utils/iokit.c`.

The mapping files can be generated with the `iomap.py` script:

```sh
export PLATFORM="$(sw_vers -productVersion)-$(sw_vers -buildVersion)"
./matching-core/sandbox_utils/iomap.py --json > "data/iomap/$PLATFORM.json"
```

Note: you need to have `ioscan` in your `PATH`, which is part of [iokit-utils](https://github.com/Siguza/iokit-utils).