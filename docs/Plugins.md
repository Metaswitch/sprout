# Plugins

Additional sproutlets can be built as plugins by placing their source code in a subdirectory of the `plugins` directory.

The plugin's source tree should have a Makefile at the top level that provides the following targets:

* `build` - which builds the plugin code.
* `test` - which builds and runs all unit tests.
* `clean` - which cleans the source tree of built objects.
* `deb-only` - which builds a deb package of the plugin.
* `deb` - which should cause both `build` and `deb-only` steps to run.

The `deb-only` step can be implemented using the `build-infra/cw-deb.mk` Makefile in the containing sprout repository.

A sample app server plugin with appropriate Makefile is provided [in the greeter repository](https://github.com/Metaswitch/greeter).

