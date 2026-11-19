"""Asterisk frame serializer.

Pipecat's ``AsteriskFrameSerializer`` only speaks G.711 mu-law. The subclass
here adds signed linear PCM (``slin16``) for wideband calls and defers to the
parent for everything else, so the Pipecat submodule stays untouched.
"""

from loguru import logger
from pipecat.frames.frames import AudioRawFrame, Frame, InputAudioRawFrame
from pipecat.serializers.asterisk import (
    AsteriskFrameSerializer as _PipecatAsteriskFrameSerializer,
)


class AsteriskFrameSerializer(_PipecatAsteriskFrameSerializer):
    """Asterisk chan_websocket serializer for mu-law or signed linear audio."""

    class InputParams(_PipecatAsteriskFrameSerializer.InputParams):
        """Configuration parameters.

        Parameters:
            media_format: Format the externalMedia channel was created with,
                ``ulaw`` or ``slin16``. It has to match the ``format`` sent
                to ARI, and ``asterisk_sample_rate`` has to match its rate.
        """

        media_format: str = "ulaw"

    @property
    def _is_linear(self) -> bool:
        return self._params.media_format != "ulaw"

    async def serialize(self, frame: Frame) -> str | bytes | None:
        """Serialize a frame; linear audio goes out as raw PCM, resampled."""
        if self._is_linear and isinstance(frame, AudioRawFrame):
            # chan_websocket expects slin in host byte order: little-endian on
            # the x86 and ARM hosts Asterisk runs on, the same as Pipecat PCM.
            data = await self._output_resampler.resample(
                frame.audio, frame.sample_rate, self._asterisk_sample_rate
            )
            return data or None
        return await super().serialize(frame)

    async def deserialize(self, data: str | bytes) -> Frame | None:
        """Deserialize Asterisk data; binary frames in linear mode are raw PCM."""
        if self._is_linear and isinstance(data, bytes):
            pcm = await self._input_resampler.resample(
                data, self._asterisk_sample_rate, self._sample_rate
            )
            if not pcm:
                return None
            return InputAudioRawFrame(
                audio=pcm, num_channels=1, sample_rate=self._sample_rate
            )
        return await super().deserialize(data)

    def _log_media_start(self, message: dict) -> None:
        """Log the terms Asterisk declares and flag a format mismatch."""
        declared_format = message.get("format")
        logger.info(
            f"Asterisk MEDIA_START: format={declared_format} "
            f"optimal_frame_size={message.get('optimal_frame_size')} "
            f"ptime={message.get('ptime')} channel_id={message.get('channel_id')}"
        )
        if declared_format and declared_format != self._params.media_format:
            logger.warning(
                f"Asterisk declared format {declared_format!r}, but this serializer "
                f"expects {self._params.media_format!r}. Audio will be garbled; "
                f"check ARI_MEDIA_FORMAT on the API and on the ARI manager."
            )


__all__ = ["AsteriskFrameSerializer"]
