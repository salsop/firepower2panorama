"""Conuntries Class."""

from fmcapi.api_objects.apiclasstemplate import APIClassTemplate
import logging
import warnings


class Countries(APIClassTemplate):
    """The Countries Object in the FMC."""

    VALID_JSON_DATA = ["id", "name", "iso2", "iso3"]
    VALID_FOR_KWARGS = VALID_JSON_DATA + []
    URL_SUFFIX = "/object/countries"
    VALID_CHARACTERS_FOR_NAME = """[.\w\d_\- ]"""

    def __init__(self, fmc, **kwargs):
        """
        Initialize Countries object.

        Set self.type to "Country" and parse the kwargs.

        :param fmc: (object) FMC object
        :param kwargs: Any other values passed during instantiation.
        :return: None
        """
        super().__init__(fmc, **kwargs)
        logging.debug("In __init__() for Countries class.")
        self.parse_kwargs(**kwargs)
        self.type = "Country"

    def post(self):
        """POST method for API for Countries not supported."""
        logging.info("POST method for API for Countries not supported.")
        pass

    def put(self):
        """PUT method for API for Countries not supported."""
        logging.info("PUT method for API for Countries not supported.")
        pass

    def delete(self):
        """DELETE method for API for Countries not supported."""
        logging.info("DELETE method for API for Countries not supported.")
        pass


class Country(Countries):
    """
    Dispose of this Class after 20210101.

    Use Countries() instead.
    """

    def __init__(self, fmc, **kwargs):
        warnings.resetwarnings()
        warnings.warn("Deprecated: Country() should be called via Countries().")
        super().__init__(fmc, **kwargs)
