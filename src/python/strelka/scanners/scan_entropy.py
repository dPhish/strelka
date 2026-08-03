import logging

import entropy
import validators
from tldextract import TLDExtract

from strelka import strelka


class ScanEntropy(strelka.Scanner):
    """Calculates entropy of files."""

    def init(self):
        self.extract = TLDExtract(suffix_list_urls=[])

    def scan(self, data, file, options, expire_at):
        entropy_data = data

        try:
            decoded = data.decode().strip()
            if validators.url(decoded):
                extracted = self.extract(decoded)
                domain = extracted.domain
                if not extracted.suffix and extracted.subdomain:
                    # Unrecognized TLD (e.g. reserved "*.test"/"*.invalid"): tldextract
                    # has nothing to split off as a suffix, so it puts the last label
                    # in `domain` instead. Fall back to the label right before it.
                    domain = extracted.subdomain.rsplit(".", 1)[-1]
                if domain:
                    entropy_data = domain.encode()
        except UnicodeDecodeError:
            pass

        logging.debug(f"Calculating entropy for data: {entropy_data}")
        self.event["entropy"] = entropy.shannon_entropy(entropy_data)
