# Development status

This repository is a private checkpoint of the core CLI. It is being reviewed
as a clean, independently sanitized source tree. Template packages are
separate repositories and are not bundled here.

The checkpoint preserves the Go `text/template` rendering model. It has not
been published as a release and has no compatibility or support commitment.

Source installs serialize trust-root generation, linker-pinned builds, and
final binary publication per installation resources. Ancestor validation is
side-effect-free before preparation, destination publication uses a bounded
same-directory temporary file and an atomic exact-leaf rename, and failures
after that rename retain committed classification. Explicit linker-pin
installs also coordinate final binary publication. This status describes the
public source-install path; it does not create a release or support commitment.
