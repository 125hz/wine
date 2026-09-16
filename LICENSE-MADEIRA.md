# Licensing of this Wine fork (LGPL branch `madeira-lgpl`)

This repository is a fork of [Wine](https://www.winehq.org/), which upstream
distributes under **LGPL-2.1-or-later**. This branch keeps that licence.

- Upstream code: LGPL-2.1-or-later, all upstream copyright and licence
  notices unchanged. Baseline: upstream tag `wine-11.4`.
- Modifications and new files authored for
  [Madeira](https://github.com/willfaust/Madeira): **LGPL-2.1-or-later**,
  Copyright (C) 2026 Will Faust. The new `dlls/wineios.drv` files are
  derived from upstream `winecoreaudio.drv` and keep its CodeWeavers and
  Huw Davies copyright notices.
- Provenance: every downstream change is one of the 51 commits listed in
  the Madeira repository's `docs/wine-lgpl-provenance.md`, cherry-picked
  from the earlier GPL-converted branch with `-x` (each commit message
  names its origin). The earlier branch's LGPL-section-3 conversion to
  GPL-3.0 is NOT applied here; that conversion is irreversible for that
  copy, which is why this branch was rebuilt from the upstream baseline
  instead.

The LGPL permits combining this library with proprietary components (such
as Apple's Metal Shader Converter) subject to LGPL-2.1 section 6; see the
Madeira repository's `docs/LICENSING.md`.
