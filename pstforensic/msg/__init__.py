"""Native MSG (Outlook ``.msg``) parser (PLAN §10, Appendix A H12).

A ``.msg`` file is a CFBF/OLE compound file ([MS-CFB]) whose directory holds
MAPI properties per [MS-OXMSG].  This subpackage reads such files into the
shared :class:`~pstforensic.mapi.MapiMessage` object model so every
``render``/``catalog`` capability works identically for MSG and PST.

Public surface:
  * :func:`pstforensic.msg.parser.open_msg`
  * :class:`pstforensic.msg.cfbf.CfbfContainer`
"""
from __future__ import annotations

from .parser import open_msg

__all__ = ["open_msg"]
