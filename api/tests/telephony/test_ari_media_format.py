"""The ARI serializer in slin16 mode moves raw PCM, resampled as needed."""

import struct

import pytest
from pipecat.frames.frames import InputAudioRawFrame, TTSAudioRawFrame

from api.services.telephony.providers.ari.serializers import AsteriskFrameSerializer


def _serializer(media_format: str, asterisk_rate: int, pipeline_rate: int):
    serializer = AsteriskFrameSerializer(
        channel_id="c1",
        ari_endpoint="http://asterisk:8088",
        app_name="app",
        app_password="secret",
        params=AsteriskFrameSerializer.InputParams(
            asterisk_sample_rate=asterisk_rate,
            sample_rate=pipeline_rate,
            media_format=media_format,
        ),
    )
    serializer._sample_rate = pipeline_rate  # what setup() would set
    return serializer


def _pcm(samples: int) -> bytes:
    return b"".join(struct.pack("<h", (i * 97) % 20000 - 10000) for i in range(samples))


@pytest.mark.asyncio
async def test_slin16_input_passes_pcm_through_at_the_same_rate():
    serializer = _serializer("slin16", 16000, 16000)
    audio = _pcm(320)  # 20 ms at 16 kHz

    frame = await serializer.deserialize(audio)

    assert isinstance(frame, InputAudioRawFrame)
    assert frame.sample_rate == 16000
    assert frame.audio == audio


@pytest.mark.asyncio
async def test_slin16_output_is_resampled_pcm_not_ulaw():
    serializer = _serializer("slin16", 16000, 16000)
    # 200 ms of 24 kHz TTS audio, the rate the OpenAI-style services return.
    frame = TTSAudioRawFrame(audio=_pcm(4800), sample_rate=24000, num_channels=1)

    data = await serializer.serialize(frame)

    # Two bytes per sample at 16 kHz (6400 bytes for 200 ms), less what the
    # streaming resampler holds back on its first block (~30 ms).
    assert isinstance(data, bytes)
    assert len(data) % 2 == 0
    assert 4000 <= len(data) <= 6400


@pytest.mark.asyncio
async def test_ulaw_stays_one_byte_per_sample():
    serializer = _serializer("ulaw", 8000, 8000)
    frame = TTSAudioRawFrame(audio=_pcm(1600), sample_rate=8000, num_channels=1)

    data = await serializer.serialize(frame)

    assert len(data) == 1600
