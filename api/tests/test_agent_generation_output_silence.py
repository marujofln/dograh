"""Bot output is dropped once an answered transfer hands the caller over."""

import pytest
from pipecat.frames.frames import (
    LLMFullResponseEndFrame,
    LLMTextFrame,
    TTSAudioRawFrame,
)
from pipecat.tests.utils import run_test

from api.services.pipecat.agent_generation_processor import AgentGenerationProcessor


def _frames():
    return [
        LLMTextFrame(text="I don't need to say anything else."),
        TTSAudioRawFrame(audio=b"\x00\x00" * 160, sample_rate=8000, num_channels=1),
        LLMFullResponseEndFrame(),
    ]


@pytest.mark.asyncio
async def test_output_passes_while_not_silenced():
    texts = []

    async def on_text(text):
        texts.append(text)

    await run_test(
        AgentGenerationProcessor(
            llm_text_frame_callback=on_text, output_silenced=lambda: False
        ),
        frames_to_send=_frames(),
        expected_down_frames=[LLMTextFrame, TTSAudioRawFrame, LLMFullResponseEndFrame],
    )
    assert texts == ["I don't need to say anything else."]


@pytest.mark.asyncio
async def test_audio_and_text_dropped_when_silenced():
    texts = []

    async def on_text(text):
        texts.append(text)

    await run_test(
        AgentGenerationProcessor(
            llm_text_frame_callback=on_text, output_silenced=lambda: True
        ),
        frames_to_send=_frames(),
        expected_down_frames=[LLMFullResponseEndFrame],
    )
    assert texts == []
