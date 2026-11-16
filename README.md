# ccsio releases

Signed release artifacts for the `ccsio` CLI. This repository holds no source.

    curl -fsSL https://raw.githubusercontent.com/Guajilodev/ccsio-releases/main/install.sh | bash

`manifest.json` names the latest release and the sha256 of every tarball; `manifest.json.sig`
is its `ssh-keygen -Y sign` signature in the `ccsio-release` namespace, made by the key in
`allowed_signers`. The installer and `ccsio update` refuse anything that does not verify.
