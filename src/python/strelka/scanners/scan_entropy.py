import logging

import entropy

from strelka import strelka


class ScanEntropy(strelka.Scanner):
    """Calculates entropy of files."""

    def scan(self, data, file, options, expire_at):
        logging.debug(f"Calculating entropy for data: {data}")
        self.event["entropy"] = entropy.shannon_entropy(data)
