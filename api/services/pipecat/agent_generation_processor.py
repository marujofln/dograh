"""One agent visit's generation, reported back to the engine.

Rides with the generation stage rather than with the call, so it sits in the
agent worker in a cascade call and on the call pipeline in a realtime one.
Both callbacks are bound to the visit that owns this processor, so a retired
agent finishing its last generation cannot disturb the running one.
"""

from typing import Awaitable, Callable, Optional

from pipecat.frames.frames import (
    Frame,
    LLMFullResponseStartFrame,
    LLMTextFrame,
    OutputAudioRawFrame,
    TTSSpeakFrame,
    TTSTextFrame,
)
from pipecat.processors.frame_processor import FrameDirection, FrameProcessor


class AgentGenerationProcessor(FrameProcessor):
    """Tell the engine when this agent starts generating and what it says."""

    def __init__(
        self,
        generation_started_callback: Optional[Callable[[], Awaitable[None]]] = None,
        llm_text_frame_callback: Optional[Callable[[str], Awaitable[None]]] = None,
        output_silenced: Optional[Callable[[], bool]] = None,
    ):
        super().__init__()
        self._generation_started_callback = generation_started_callback
        self._llm_text_frame_callback = llm_text_frame_callback
        self._output_silenced = output_silenced

    async def process_frame(self, frame: Frame, direction: FrameDirection):
        await super().process_frame(frame, direction)

        # Once the caller belongs to someone else (a transfer was answered), a
        # realtime model that still answers the tool result must not be heard
        # or enter the transcript.
        if (
            direction == FrameDirection.DOWNSTREAM
            and self._output_silenced
            and self._output_silenced()
            and isinstance(
                frame, (OutputAudioRawFrame, LLMTextFrame, TTSTextFrame, TTSSpeakFrame)
            )
        ):
            return

        if (
            isinstance(frame, LLMFullResponseStartFrame)
            and self._generation_started_callback
        ):
            await self._generation_started_callback()
        elif (
            isinstance(frame, (LLMTextFrame, TTSSpeakFrame))
            and self._llm_text_frame_callback
        ):
            # Static nodes speak through TTSSpeakFrame rather than the LLM, so
            # both carry reference text for correcting the aggregated transcript.
            await self._llm_text_frame_callback(frame.text)

        await self.push_frame(frame, direction)
