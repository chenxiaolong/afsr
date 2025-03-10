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

[Issue #2]: https://github.com/chenxiaolong/afsr/issues/2
[Issue #7]: https://github.com/chenxiaolong/afsr/issues/7
[Issue #13]: https://github.com/chenxiaolong/afsr/issues/13
[PR #5]: https://github.com/chenxiaolong/afsr/pull/5
[PR #6]: https://github.com/chenxiaolong/afsr/pull/6
[PR #8]: https://github.com/chenxiaolong/afsr/pull/8
[PR #10]: https://github.com/chenxiaolong/afsr/pull/10
[PR #11]: https://github.com/chenxiaolong/afsr/pull/11
[PR #12]: https://github.com/chenxiaolong/afsr/pull/12
[PR #15]: https://github.com/chenxiaolong/afsr/pull/15
[PR #16]: https://github.com/chenxiaolong/afsr/pull/16
