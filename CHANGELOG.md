# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]
- Refactored connection.c and updated corresponding unit tests
- Additional `/cloud-status` and `/cloud-disconnect` fields.
- Switched from nanomsg (Release 1.1.2) to NNG (Release v1.0.1)
- Memory leak fixes
- Changed connection logic (connection.c) for retries, and added unit test
- Reverted from NNG to nanomag (v1.1.2)
- use version # in git_tag
- removed unnecessary file libpd_test.c

## [1.0.1] - 2018-07-18
### Added
- Added command line arguments for secure token read and acquire.
- DNS check for <device-id>.<URL> to allow custom device handling logic (like test boxes, refurbishing, etc).
- Add check for matching `partner-id` for incoming WRP messages based on command line argument passed.
- CRUD operations to local namespace is now supported.
- Via CRUD calls, the custom metadata tag values are now supported.

### Changed
- Configurable security flag and port.
- Default HTTP port to 80 and HTTPS port to 443.
- Updates to how `nopoll` is called have been implemented.

### Fixed
- 64 bit pointer fixes (#144, #145).
- Handle `403` error from talaria (#147).
- Several additional NULL pointer checks & recovery logic blocks added.
- A scenario where ping requests are not responded to was fixed. 

### Security
- Added command line arguments for secure token read and acquire.  Token presented to cloud for authentication verification.

## [1.0.0] - 2017-11-17
### Added
- Added the basic implementation.

## [0.0.1] - 2016-08-15
### Added
- Initial creation

[Unreleased]: https://github.com/Comcast/parodus/compare/1.0.1...HEAD
[1.0.1]: https://github.com/Comcast/parodus/compare/1.0.0...1.0.1
[1.0.0]: https://github.com/Comcast/parodus/compare/79fa7438de2b14ae64f869d52f5c127497bf9c3f...1.0.0

