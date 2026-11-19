"""Audio format of the externalMedia channel between Asterisk and Dograh.

``ARI_MEDIA_FORMAT`` picks the format Asterisk is asked for when the
externalMedia channel is created, and the rate the pipeline then runs at:

- ``ulaw`` (default): G.711 mu-law at 8 kHz, the narrowband telephone format.
- ``slin16``: 16-bit signed linear PCM at 16 kHz. Asterisk transcodes the
  caller's codec to it, so a wideband leg (Opus from WhatsApp, G.722 from a
  desk phone) reaches STT with its upper band intact. 16 kHz is the ceiling of
  the Dograh pipeline (``AudioConfig``), so a higher rate would buy nothing.

The ARI manager (which creates the channel) and the API (which builds the
transport) read the same variable, so both processes must be given the same
value.
"""

import os

_SAMPLE_RATES = {"ulaw": 8000, "slin16": 16000}

ARI_MEDIA_FORMAT = os.getenv("ARI_MEDIA_FORMAT", "ulaw").strip().lower()
if ARI_MEDIA_FORMAT not in _SAMPLE_RATES:
    raise ValueError(
        f"ARI_MEDIA_FORMAT={ARI_MEDIA_FORMAT!r} is not supported; "
        f"use one of {sorted(_SAMPLE_RATES)}"
    )

ARI_MEDIA_SAMPLE_RATE = _SAMPLE_RATES[ARI_MEDIA_FORMAT]
