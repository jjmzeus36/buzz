# Third-party notices for the bundled Opus decoder

The published NetEq 0.8.3 source includes
`src/scripts/opus-decoder.min.js`. These notices accompany that existing asset;
its bytes and the NetEq source provenance remain unchanged.

## Asset identity

- Package: `opus-decoder` 0.7.10.
- Asset SHA-256:
  `9966804c4a270affa2ad96b8dcf0ed66a4a94811a116e068693e99106346dfb7`.
- [Published npm package](https://registry.npmjs.org/opus-decoder/0.7.10).
- npm archive integrity:
  `sha512-qUZdyAK+kKy/wUSd/oZ0ULE9U/yskp332n2oBvSP/Jz/wHsHiVRg33f/tRUR8TRiw+ka7AQUclxcr5TbUJo+VA==`.
- Upstream revision: `2f95b884eb0ceefdbeedbe245766cfe51ef91640`.
- [Exact upstream asset](https://github.com/eshaz/wasm-audio-decoders/blob/2f95b884eb0ceefdbeedbe245766cfe51ef91640/src/opus-decoder/dist/opus-decoder.min.js).

The vendored file matches both the npm artifact and this upstream asset byte for
byte. The upstream [licensing and attribution documentation](https://github.com/eshaz/wasm-audio-decoders/blob/2f95b884eb0ceefdbeedbe245766cfe51ef91640/README.md#licensing)
identifies separately licensed decoding libraries compiled into distribution
files, and `puff` compiled to WASM for decompression.

## wasm-audio-decoders / opus-decoder

Copyright 2021-2025 Ethan Halsall.

The [package declares MIT](https://github.com/eshaz/wasm-audio-decoders/blob/2f95b884eb0ceefdbeedbe245766cfe51ef91640/src/opus-decoder/package.json).
[LICENSE-OPUS-DECODER-MIT](LICENSE-OPUS-DECODER-MIT) reproduces the MIT text with
the copyright notice from the asset's banner. The text is from the
[SPDX MIT template](https://github.com/spdx/license-list-data/blob/31ba1a50e5397e00a304dbadc76531740e89ee48/text/MIT.txt);
upstream's package does not supply a separate license file.

## libopus

The decoder repository's [pinned submodule](https://github.com/eshaz/wasm-audio-decoders/tree/2f95b884eb0ceefdbeedbe245766cfe51ef91640/modules/opus)
is `xiph/opus` revision `ddbe48383984d56acd9e1ab6a090c54ca6b735a6`.
[LICENSE-LIBOPUS](LICENSE-LIBOPUS) is an unchanged copy of that revision's
[COPYING](https://github.com/xiph/opus/blob/ddbe48383984d56acd9e1ab6a090c54ca6b735a6/COPYING),
including its copyright, redistribution conditions, disclaimer, and patent
license references. Keep it with distributions containing the compiled decoder.

## puff

Copyright (C) 2002-2013 Mark Adler, all rights reserved.

[LICENSE-PUFF](LICENSE-PUFF) reproduces the complete license comment from the
[pinned upstream puff.h](https://github.com/eshaz/wasm-audio-decoders/blob/2f95b884eb0ceefdbeedbe245766cfe51ef91640/src/common/src/puff/puff.h).
The bundled decoder includes its compiled WASM decompressor.

## Distribution coverage

Keep this document and the three referenced license files with redistributions
of the vendored source or the bundled decoder. These additions cover the bundled
asset's notices in the source tree. NetEq itself retains its existing
[MIT](LICENSE-MIT) and [Apache](LICENSE-APACHE) alternatives.

Buzz's current desktop dependency disables NetEq's web features. This document
does not configure installer resources: distributors must separately include the
selected NetEq license and applicable third-party notices in any final binary
package that contains those components, then inspect the resulting package.
