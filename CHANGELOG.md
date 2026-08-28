<!--
    When adding new changelog entries, use [Issue #0] to link to issues and
    [PR #0] to link to pull requests. Then run:

        cargo xtask update-changelog

    to update the actual links at the bottom of the file.
-->

### Unreleased

* Add support for erofs filesystems ([Issue #14], [PR #24])
  * **NOTE**: There is a breaking change to the `fs_metadata.toml` file format. The `entries` section is the same as before, but other top level keys have been moved to a filesystem-specific `metadata` section.
* Add support for tab completion of commands ([PR #26])
* Update dependencies ([PR #22])
* Remove support for using the system e2fsprogs library on Linux ([PR #23])
  * All platforms will now use Android's fork of e2fsprogs.

### Version 1.0.4

* Add prebuilt binaries for aarch64 GNU/Linux and Windows ([PR #21])

### Version 1.0.3

* Update dependencies ([PR #15])
* Fix panic when parsing nanosecond timestamp values >= 2^30 (536870912) due to incorrect mathematical order of operations ([Issue #13], [PR #16])

### Version 1.0.2

* Make use of Rust 1.83's newly added `io::ErrorKind`s for better error messages ([PR #10])
* Update dependencies ([PR #11])
* Fix new clippy 1.83 warnings ([PR #12])

### Version 1.0.1

* Fix creating filesystems on Windows when a Unicode output path is used ([Issue #7], [PR #8])

### Version 1.0.0

* Initial binary release ([Issue #2], [PR #5])
* Update dependencies ([PR #6])

<!-- Do not manually edit the lines below. Use `cargo xtask update-changelog` to regenerate. -->
[Issue #2]: https://github.com/chenxiaolong/afsr/issues/2
[Issue #7]: https://github.com/chenxiaolong/afsr/issues/7
[Issue #13]: https://github.com/chenxiaolong/afsr/issues/13
[Issue #14]: https://github.com/chenxiaolong/afsr/issues/14
[PR #5]: https://github.com/chenxiaolong/afsr/pull/5
[PR #6]: https://github.com/chenxiaolong/afsr/pull/6
[PR #8]: https://github.com/chenxiaolong/afsr/pull/8
[PR #10]: https://github.com/chenxiaolong/afsr/pull/10
[PR #11]: https://github.com/chenxiaolong/afsr/pull/11
[PR #12]: https://github.com/chenxiaolong/afsr/pull/12
[PR #15]: https://github.com/chenxiaolong/afsr/pull/15
[PR #16]: https://github.com/chenxiaolong/afsr/pull/16
[PR #21]: https://github.com/chenxiaolong/afsr/pull/21
[PR #22]: https://github.com/chenxiaolong/afsr/pull/22
[PR #23]: https://github.com/chenxiaolong/afsr/pull/23
[PR #24]: https://github.com/chenxiaolong/afsr/pull/24
[PR #26]: https://github.com/chenxiaolong/afsr/pull/26
