"""RevFuzz 分级日志助手 —— P6。

团队 main.py（P1）已通过 stdlib logging 配置全局日志（日志器名 "revfuzz"）；
本模块为业务模块与独立测试提供便捷接口：

- get_logger(module)：返回 "revfuzz.<module>" 子日志器，自动继承 P1 的日志配置；
- init_logger(...)：幂等，仅在 "revfuzz" 根日志器尚无 handler 时生效，
  避免覆盖 P1 已建立的 setup_logging 配置。

统一格式（独立初始化时）：[时间] [级别] [模块名] 内容
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path

_LOGGER_NAME = "revfuzz"
_LOG_FORMAT = "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s"
_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"

# 独立初始化时的文件滚动参数：超过 10MB 自动换新文件，最多保留 5 个
_MAX_BYTES = 10 * 1024 * 1024
_BACKUP_COUNT = 5
_LOG_FILE_PREFIX = "revfuzz_"


def get_logger(module: str = "root") -> logging.Logger:
    """获取带模块名的日志器，挂载在 "revfuzz" 根日志器之下。

    Args:
        module: 业务模块名（如 "reporter"），会显示在日志的 [模块名] 中。

    Returns:
        可直接调用 debug/info/error 的 logging.Logger 实例。
    """
    return logging.getLogger(f"{_LOGGER_NAME}.{module}" if module != "root" else _LOGGER_NAME)


def init_logger(output_dir: str | Path = "out", debug: bool = False) -> logging.Logger:
    """幂等初始化日志器：仅当 "revfuzz" 根日志器尚无 handler 时生效。

    若 main.py（P1）已经 setup_logging 过，本函数直接返回现有根日志器，
    避免清空或覆盖团队已建立的日志配置。

    Args:
        output_dir: 日志文件所在目录，不存在会自动创建。
        debug: True 时开启 DEBUG 级日志，否则默认 INFO 级。

    Returns:
        配置完成的根日志器。
    """
    root = logging.getLogger(_LOGGER_NAME)
    if root.handlers:
        # 已被 main.py 配置，直接复用，保证团队日志配置不被破坏
        return root

    root.setLevel(logging.DEBUG if debug else logging.INFO)
    root.propagate = False

    formatter = logging.Formatter(_LOG_FORMAT, datefmt=_TIME_FORMAT)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    root.addHandler(console)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / f"{_LOG_FILE_PREFIX}{_timestamp()}.log"
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setFormatter(formatter)
    root.addHandler(file_handler)

    return root


def _timestamp() -> str:
    """生成日志文件名的本地时间戳，例如 20260819_163000。"""
    return datetime.now().strftime("%Y%m%d_%H%M%S")
