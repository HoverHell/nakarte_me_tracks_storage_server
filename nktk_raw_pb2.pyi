from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Optional as _Optional

DESCRIPTOR: _descriptor.FileDescriptor

class TrackView(_message.Message):
    __slots__ = ("view", "track")
    VIEW_FIELD_NUMBER: _ClassVar[int]
    TRACK_FIELD_NUMBER: _ClassVar[int]
    view: bytes
    track: bytes
    def __init__(self, view: _Optional[bytes] = ..., track: _Optional[bytes] = ...) -> None: ...
