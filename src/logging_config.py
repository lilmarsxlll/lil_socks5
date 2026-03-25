import logging


def setup_logging():
    logging.basicConfig(format="%(levelname)s:%(message)s", level=logging.DEBUG)


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(name)
